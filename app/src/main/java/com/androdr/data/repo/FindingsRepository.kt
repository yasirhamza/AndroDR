package com.androdr.data.repo

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.map
import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.Converters
import com.androdr.data.db.FindingKinds
import com.androdr.data.db.FindingRow
import com.androdr.data.db.FindingSummaryCounts
import com.androdr.data.db.AlertGroupRow
import com.androdr.data.db.StoredFindingCounts
import com.androdr.data.db.chunkedIn
import com.androdr.data.model.Alert
import com.androdr.data.model.AlertStatus
import com.androdr.data.model.FindingKind
import com.androdr.data.model.FindingRowColumns
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanFinding
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanWithFindings
import com.androdr.data.store.ChunkResult
import com.androdr.data.store.DecodedRecord
import com.androdr.data.store.HashKeys
import com.androdr.data.store.KeysetPagingSource
import com.androdr.data.store.TelemetryReader
import com.androdr.data.store.tableChanges
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEvaluator
import com.androdr.sigma.TaxonomyContract
import com.androdr.ui.security.ConfirmResult
import com.androdr.ui.security.DeviceSecurity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/**
 * What is current (spec §5.4 Lifecycle): the latest live scan's triggered state findings (bounded
 * by rules × live records) and how many alerts are OPEN.
 */
data class CurrentFindingsSummary(val stateFindings: List<Finding>, val openAlertCount: Int) {
    /** Current findings = triggered state findings ∪ OPEN alerts. */
    val count: Int get() = stateFindings.size + openAlertCount

    companion object {
        val EMPTY = CurrentFindingsSummary(emptyList(), 0)
    }
}

/** One alert as the open-alerts list shows it, with its authoritative evidence decoded. */
data class AlertView(
    val id: Long,
    val ruleId: String,
    val level: String,
    val status: AlertStatus,
    val openedAt: Long,
    val openedScanId: Long,
    val lastActivityAt: Long,
    val recordId: Long?,
    val evidence: Finding?,
    val matchedValue: String = "",
    val closedAt: Long? = null,
    val closedReason: String? = null,
    val closedWithCredential: Boolean = false,
) {
    companion object {
        fun of(a: Alert) = AlertView(a.id, a.ruleId, a.level, a.status, a.openedAt, a.openedScanId,
            a.lastActivityAt, a.recordId, Converters.decodeFinding(a.evidenceJson), a.matchedValue, a.closedAt,
            a.closedReason, a.closedWithCredential)
    }
}

/** Identifies one open-alert group, bounded to the alerts the person saw (`id <= maxId`). */
data class AlertGroupRef(val ruleId: String, val matchedValue: String, val maxId: Long)

/**
 * One group of OPEN alerts as the dashboard lists it (spec §5.4: grouped by rule and matched value):
 * how many, their latest activity, and the newest alert ([sample]) for its title and level.
 */
data class AlertGroup(
    val ruleId: String,
    val matchedValue: String,
    val count: Int,
    val lastActivityAt: Long,
    val maxId: Long,
    val sample: AlertView?,
) {
    val ref: AlertGroupRef get() = AlertGroupRef(ruleId, matchedValue, maxId)
}

/** A stored finding with its row id (the paging key). */
class StoredFinding(val id: Long, val finding: Finding)

/**
 * Per-scan findings (`scan_finding`) and lasting alerts (`alert`), spec §5.4.
 *
 * Writer side: every `record*` function is transaction-agnostic and runs inside the writer session's
 * transactions (a chunk's persist, or the finishing transaction); [createAlertsForScan] runs only in
 * the finishing transaction. Reader side: every read requires the finding's scan to be `COMPLETE`.
 * A finding stored with a `recordId` omits its `matchContext`; readers rebuild it from the fact as
 * the finding's own scan observed it ([SigmaRuleEvaluator.matchContextOf], the evaluator's own
 * definition).
 */
@Singleton
@Suppress("TooManyFunctions") // the writer's record/alert steps and the readers' views of one table pair
class FindingsRepository @Inject constructor(
    private val db: AppDatabase,
    private val reader: TelemetryReader,
    private val deviceSecurity: DeviceSecurity,
) {
    private val findings get() = db.scanFindingDao()
    private val alerts get() = db.alertDao()
    private val scans get() = db.scanResultDao()

    // ── Writer side ───────────────────────────────────────────────────────────────────────────

    /**
     * Writes [scanId]'s findings for one persisted chunk (ordinals `firstOrdinal ..`): only those
     * whose ordinal this scan newly observed ([ChunkResult.observedThisScanByChunkIndex]), so a
     * duplicate record or an already-observed live event yields no second finding. A finding's fact
     * is [ChunkResult.factIdByChunkIndex] (or its own `recordId`, from `evaluateStored`); its kind
     * follows [ChunkResult.isEventByChunkIndex]. [row] builds a triggered finding's Timeline row.
     * Returns the findings written.
     */
    suspend fun recordChunk(
        scanId: Long, firstOrdinal: Int, findings: List<Finding>, chunk: ChunkResult,
        row: (Finding) -> ForensicTimelineEvent,
    ): List<Finding> {
        val kept = ArrayList<Finding>()
        val pending = ArrayList<Pending>()
        for (f in findings) {
            val i = f.ordinal - firstOrdinal
            if (i !in chunk.observedThisScanByChunkIndex.indices || !chunk.observedThisScanByChunkIndex[i]) continue
            val recordId = f.recordId ?: chunk.factIdByChunkIndex[i]
            val kind = if (chunk.isEventByChunkIndex[i]) FindingKind.ALERT else FindingKind.STATE
            kept += f
            if (keepsRow(f)) pending += Pending(f, recordId, kind)
        }
        insert(scanId, pending, row)
        return kept
    }

    /**
     * The late-IOC re-check's findings (spec §5.2): each carries `recordId = factId` (`ordinal = -1`);
     * re-checked facts are live DNS events, so these are alerts.
     */
    suspend fun recordStored(scanId: Long, findings: List<Finding>, row: (Finding) -> ForensicTimelineEvent) {
        insert(scanId, findings.map { f ->
            val kind = if (f.service in TaxonomyContract.eventServices) FindingKind.ALERT else FindingKind.STATE
            Pending(f, checkNotNull(f.recordId) { "a re-check finding carries its fact" }, kind)
        }.filter { keepsRow(it.finding) }, row)
    }

    /**
     * Evaluate-only findings (spec §5.2: a full disk or a breached import reserve): no fact, so the
     * kind follows [FindingKinds.noFact] and the alert key [AlertIdentity.noFactKey]; they keep
     * their `matchContext`.
     */
    suspend fun recordNoFact(scanId: Long, findings: List<Finding>, row: (Finding) -> ForensicTimelineEvent) {
        insert(scanId, findings.filter(::keepsRow).map { f ->
            val field = TaxonomyContract.eventTimeField(f.service)
            Pending(f, null, FindingKinds.noFact(f.service.ifEmpty { null }, field, f.matchContext))
        }, row)
    }

    /** Correlation findings: STATE rows of their scan, no alert, no Timeline row (the signal is the row). */
    suspend fun recordState(scanId: Long, findings: List<Finding>) {
        if (findings.isEmpty()) return
        this.findings.insertAll(findings.map { f ->
            ScanFinding(scanId = scanId, ruleId = f.ruleId, triggered = f.triggered, level = f.level,
                category = f.category.name, kind = FindingKind.STATE, recordId = null, service = f.service,
                ordinal = f.ordinal, alertKey = null, alertId = null, findingJson = Converters.encodeFinding(f),
                evidenceJson = null, row = null)
        })
    }

    /**
     * Inside the finishing transaction: opens one alert per new key among [scanId]'s findings
     * (set-based), attaches every keyed finding, re-surfaces the alerts they attached to, and checks
     * that no keyed finding is left unattached (throwing rolls the finish back).
     */
    suspend fun createAlertsForScan(scanId: Long, at: Long) {
        alerts.openForScan(scanId, at)
        alerts.attachForScan(scanId)
        alerts.touchForScan(scanId, at)
        val unattached = findings.unattachedCount(scanId)
        check(unattached == 0) { "$unattached finding(s) of scan $scanId have an alert key but no alert" }
        findings.clearEvidence(scanId)
    }

    /** Of [keys], those that already have an alert (byte content compared). */
    suspend fun existingAlertKeys(keys: Collection<ByteArray>): Set<java.nio.ByteBuffer> = alertIdsByKey(keys).keys

    /** Of [keys], those that already have an alert, with that alert's id (byte content compared). */
    private suspend fun alertIdsByKey(keys: Collection<ByteArray>): Map<java.nio.ByteBuffer, Long> =
        chunkedIn(keys.distinctBy(HashKeys::key)) { alerts.idsForKeys(it) }.associate { HashKeys.key(it.key) to it.id }

    private class Pending(val finding: Finding, val recordId: Long?, val kind: FindingKind)

    /** Untriggered (safe-state) findings are stored only for snapshot services (spec §5.4). */
    fun keepsRow(f: Finding): Boolean = f.triggered || f.service !in TaxonomyContract.eventServices

    private suspend fun insert(scanId: Long, pending: List<Pending>, row: (Finding) -> ForensicTimelineEvent) {
        if (pending.isEmpty()) return
        val keys = pending.map { alertKey(scanId, it) }
        val existing = alertIdsByKey(keys.filterNotNull())
        findings.insertAll(pending.mapIndexed { i, p ->
            val f = p.finding
            val key = keys[i]
            val full = f.copy(recordId = p.recordId)
            // matchContext is dropped only when the fact is stored (readers rebuild it from there).
            val stored = if (p.recordId != null) full.copy(matchContext = emptyMap()) else full
            // A key that already has an alert is attached now (review Minor 7); only a new key may open one.
            val alertId = key?.let { existing[HashKeys.key(it)] }
            // A row with a stored fact carries its full opening finding transiently; a no-fact row's
            // findingJson already is that finding, so it carries nothing extra (review Minor 5).
            val opens = key != null && alertId == null && p.recordId != null
            ScanFinding(
                scanId = scanId, ruleId = f.ruleId, triggered = f.triggered, level = f.level,
                category = f.category.name, kind = p.kind, recordId = p.recordId, service = f.service,
                ordinal = f.ordinal, alertKey = key, alertId = alertId,
                findingJson = Converters.encodeFinding(stored),
                matchedValue = key?.let { AlertIdentity.Discriminator.of(f.evidence).matchedValue },
                evidenceJson = if (opens) Converters.encodeFinding(full) else null,
                row = if (f.triggered) rowColumns(f, row) else null,
            )
        })
    }

    private fun alertKey(scanId: Long, p: Pending): ByteArray? {
        val f = p.finding
        if (!f.triggered || p.kind != FindingKind.ALERT) return null
        return if (p.recordId != null) {
            AlertIdentity.recordKey(f.ruleId, p.recordId, f.evidence)
        } else {
            val time = FindingKinds.eventTime(TaxonomyContract.eventTimeField(f.service), f.matchContext)
            AlertIdentity.noFactKey(f.ruleId, f.evidence, time, scanId, f.ordinal)
        }
    }

    private fun rowColumns(f: Finding, row: (Finding) -> ForensicTimelineEvent): FindingRowColumns {
        val r = row(f)
        check(r.level == f.level) { "finding row for ${f.ruleId} must carry its level" }
        return FindingRowColumns.of(r)
    }

    // ── Reader side ───────────────────────────────────────────────────────────────────────────

    /**
     * Every finding of COMPLETE scan [scanId] (triggered first), in recording order, as one list. Only
     * for scans whose findings are bounded — live scans (rules × live records) and tests; anything
     * that may read an import streams with [forEachFinding] (review C1/I1: an import can hold 100k).
     */
    suspend fun findingsOf(scanId: Long, triggeredOnly: Boolean = false): List<Finding> {
        val out = ArrayList<Finding>()
        forEachFinding(scanId, triggeredOnly) { out += it }
        return out
    }

    /**
     * Streams every finding of COMPLETE scan [scanId] (triggered first, in recording order) through
     * [block], one keyset page ([READ_BATCH]) decoded at a time, so no reader holds a whole scan.
     */
    suspend fun forEachFinding(scanId: Long, triggeredOnly: Boolean = false, block: suspend (Finding) -> Unit) {
        for (triggered in if (triggeredOnly) listOf(true) else listOf(true, false)) {
            var after = 0L
            while (true) {
                val page = findings.page(scanId, triggered, after, READ_BATCH)
                for (f in decode(scanId, page)) block(f)
                if (page.size < READ_BATCH) break
                after = page.last().id
            }
        }
    }

    /** [scan] with its findings ([findingsOf]): bounded scans only (live scans, tests). */
    suspend fun withFindings(scan: ScanResult, triggeredOnly: Boolean = false): ScanWithFindings =
        ScanWithFindings(scan, findingsOf(scan.id, triggeredOnly))

    /** Triggered findings per rule of COMPLETE scan [scanId] (bounded by the rule count), in SQL. */
    suspend fun triggeredRuleCounts(scanId: Long): Map<String, Int> =
        findings.triggeredRuleCounts(scanId).associate { it.ruleId to it.count }

    /** Up to [size] triggered findings of [ruleId] in COMPLETE scan [scanId], in recording order. */
    suspend fun ruleSample(scanId: Long, ruleId: String, size: Int): List<Finding> =
        decode(scanId, findings.ruleSample(scanId, ruleId, size))

    /** The History sheet's counts for COMPLETE scan [scanId], computed in SQL (never decoded). */
    suspend fun summaryCounts(scanId: Long): FindingSummaryCounts = findings.summaryCounts(scanId)

    /** The newest COMPLETE live scan with every finding (bounded by rules × live records), on change. */
    fun latestLive(): Flow<ScanWithFindings?> = db.tableChanges(arrayOf("ScanResult"))
        .map { scans.latestLiveOnce()?.let { withFindings(it) } }
        .flowOn(Dispatchers.IO)

    /** Current findings (spec §5.4): re-read when a scan completes or is deleted, or an alert changes. */
    fun current(): Flow<CurrentFindingsSummary> = db.tableChanges(arrayOf("ScanResult", "alert"))
        .map { currentOnce() }
        .flowOn(Dispatchers.IO)

    /** [current], read once. */
    suspend fun currentOnce(): CurrentFindingsSummary {
        val rows = findings.currentState()
        return CurrentFindingsSummary(decode(rows.firstOrNull()?.scanId, rows), alerts.openCount())
    }

    /** OPEN alerts, most recent activity first, keyset-paged. */
    fun openAlerts(): Flow<PagingData<AlertView>> =
        Pager(PagingConfig(pageSize = PAGE_SIZE, enablePlaceholders = false)) { OpenAlertPagingSource(db) }.flow

    /** One COMPLETE scan's triggered findings, in recording order, keyset-paged. */
    fun forScan(scanId: Long): Flow<PagingData<Finding>> =
        Pager(PagingConfig(pageSize = PAGE_SIZE, enablePlaceholders = false)) { ScanFindingPagingSource(scanId) }
            .flow.map { page -> page.map { it.finding } }

    /** Triggered, non-informational findings of COMPLETE scan [scanId] (the import screen's count). */
    suspend fun shownCount(scanId: Long): Int = findings.triggeredShownCount(scanId)

    /**
     * Closes the OPEN alerts among [alertIds] (spec §5.4 Closing an alert) — only after the device
     * credential was [ConfirmResult.Confirmed] (`closedWithCredential = 1`), or on
     * [ConfirmResult.NoSecureLock] when a re-check finds no secure lock screen
     * (`closedWithCredential = 0`). Anything else — cancelled, or "no secure lock" on a device that
     * is secure — closes nothing (fails closed). A close that changes alerts writes one persistent
     * `alert_closed` Timeline row in the same transaction. Returns how many closed.
     */
    suspend fun close(alertIds: List<Long>, reason: String?, result: ConfirmResult): Int {
        if (alertIds.isEmpty()) return 0
        val withCredential = credentialOf(result) ?: return 0
        val now = System.currentTimeMillis()
        return db.withTransaction {
            val groups = mergeGroups(chunkedIn(alertIds) { alerts.openGroupsOf(it) })
            val closed = chunkedIn(alertIds) { listOf(alerts.closeOpen(it, now, reason, withCredential)) }.sum()
            if (closed > 0) {
                db.forensicTimelineEventDao().insert(
                    closedRow(
                        groups.map { it.ruleId to it.matchedValue to it.count }, closed, reason, withCredential, now,
                    )
                )
            }
            closed
        }
    }

    /**
     * Bulk close by group (the open-alerts list, spec §5.4): each group's OPEN alerts up to its
     * [AlertGroupRef.maxId] — those the person saw — under one confirmation, with the same
     * confirmation rule and `alert_closed` row as [close]. Returns how many closed.
     */
    suspend fun closeGroups(groups: List<AlertGroupRef>, reason: String?, result: ConfirmResult): Int {
        if (groups.isEmpty()) return 0
        val withCredential = credentialOf(result) ?: return 0
        val now = System.currentTimeMillis()
        return db.withTransaction {
            val closedByGroup = groups.distinct().map { g ->
                g to alerts.closeGroup(g.ruleId, g.matchedValue, g.maxId, now, reason, withCredential)
            }
            val closed = closedByGroup.sumOf { it.second }
            if (closed > 0) {
                val lines = closedByGroup.filter { it.second > 0 }.map { (g, n) -> g.ruleId to g.matchedValue to n }
                db.forensicTimelineEventDao().insert(closedRow(lines, closed, reason, withCredential, now))
            }
            closed
        }
    }

    /** `closedWithCredential` for [result], or null when the close must be refused. */
    private fun credentialOf(result: ConfirmResult): Boolean? = when (result) {
        ConfirmResult.Confirmed -> true
        // Honoured only when the lock screen really is insecure; otherwise refused (fails closed).
        ConfirmResult.NoSecureLock -> if (deviceSecurity.isDeviceSecure()) null else false
        ConfirmResult.Cancelled -> null
    }

    private fun mergeGroups(rows: List<AlertGroupRow>): List<AlertGroupRow> =
        rows.groupBy { it.ruleId to it.matchedValue }.map { (_, g) ->
            g.first().copy(count = g.sumOf { it.count }, lastActivityAt = g.maxOf { it.lastActivityAt },
                maxId = g.maxOf { it.maxId })
        }

    /** The persistent `alert_closed` row: what closed (capped), the note and the credential flag. */
    private fun closedRow(
        groups: List<Pair<Pair<String, String>, Int>>, closed: Int, reason: String?, withCredential: Boolean, now: Long,
    ): ForensicTimelineEvent {
        val sb = StringBuilder()
        sb.append("Note: ").append(reason?.takeIf { it.isNotBlank() }?.take(MAX_NOTE) ?: "(none)")
        sb.append("\nClosed with device credential: ")
            .append(if (withCredential) "yes" else "no (no secure lock screen)")
        var listed = 0
        for ((key, n) in groups.sortedByDescending { it.second }.take(MAX_CLOSED_LINES)) {
            sb.append("\n").append(key.first.take(MAX_RULE)).append(" · ")
                .append(key.second.ifEmpty { "—" }.take(MAX_VALUE)).append(" × ").append(n)
            listed += n
        }
        if (closed > listed) sb.append("\n…and ").append(closed - listed).append(" more alert(s)")
        return ForensicTimelineEvent(
            startTimestamp = now, source = CLOSED_SOURCE, category = CLOSED_CATEGORY,
            description = "Closed $closed alert(s)", details = sb.toString(), createdAt = now, persistent = true,
        )
    }

    /** OPEN alerts grouped by rule and matched value (spec §5.4), most recent activity first, keyset-paged. */
    fun openAlertGroups(): Flow<PagingData<AlertGroup>> =
        Pager(PagingConfig(pageSize = GROUP_PAGE_SIZE, enablePlaceholders = false)) { OpenAlertGroupPagingSource(db) }
            .flow

    /** The OPEN alerts of a finding row (its rule on its fact): a Timeline row's Close. */
    suspend fun openAlertIdsFor(ruleId: String, recordId: Long?): List<Long> =
        if (recordId == null || ruleId.isEmpty()) emptyList() else alerts.openIdsFor(ruleId, recordId)

    /**
     * Streams every alert with [status], most recent activity first, in keyset pages of
     * [READ_BATCH] (the report, spec §5.4): never more than one page in memory.
     */
    suspend fun forEachAlert(status: AlertStatus, block: suspend (AlertView, DecodedRecord?) -> Unit) {
        var at = Long.MAX_VALUE
        var id = Long.MAX_VALUE
        while (true) {
            val page = alerts.byStatusAfter(status.name, at, id, READ_BATCH)
            // Each alert's matched fact ("Matched record"): pinned by the alert, so it survives scans.
            val records = chunkedIn(page.mapNotNull { it.recordId }.distinct()) { reader.records(it) }
                .associateBy { it.factId }
            for (a in page) block(AlertView.of(a), a.recordId?.let(records::get))
            if (page.size < READ_BATCH) return
            at = page.last().lastActivityAt
            id = page.last().id
        }
    }

    /** A History row's stored counts (shown and stored triggered findings), in SQL. */
    suspend fun rowCounts(scanId: Long): StoredFindingCounts = findings.rowCounts(scanId)

    /** Alerts by id (the report and detail views). */
    suspend fun alerts(ids: List<Long>): List<AlertView> = chunkedIn(ids) { alerts.alertsByIds(it) }.map(AlertView::of)

    private suspend fun decode(scanId: Long?, rows: List<FindingRow>): List<Finding> =
        decodeStored(scanId, rows).map { it.finding }

    /** Decodes rows of one scan, rebuilding `matchContext` from each row's fact when it was dropped. */
    private suspend fun decodeStored(scanId: Long?, rows: List<FindingRow>): List<StoredFinding> {
        val parsed = rows.mapNotNull { r -> Converters.decodeFinding(r.findingJson)?.let { r to it } }
        val missing = parsed.mapNotNull { (r, f) -> r.recordId?.takeIf { f.matchContext.isEmpty() } }
        val context = if (missing.isEmpty() || scanId == null) {
            emptyMap()
        } else {
            reader.recordsInScan(scanId, missing)
                .associate { it.factId to it.fields?.let(SigmaRuleEvaluator::matchContextOf) }
        }
        return parsed.map { (r, f) ->
            val rebuild = r.recordId != null && f.matchContext.isEmpty()
            val ctx = if (rebuild) context[r.recordId].orEmpty() else f.matchContext
            StoredFinding(r.id, f.copy(recordId = r.recordId ?: f.recordId, matchContext = ctx))
        }
    }

    private inner class ScanFindingPagingSource(private val scanId: Long) :
        KeysetPagingSource<Long, StoredFinding>(db, KeysetPagingSource.OBSERVED_TABLES) {
        override fun keyOf(item: StoredFinding): Long = item.id
        override suspend fun loadFrom(from: Long?, size: Int) =
            slice(decodeStored(scanId, findings.page(scanId, true, (from ?: 1L) - 1, size)))
        override suspend fun loadAfter(after: Long, size: Int) =
            slice(decodeStored(scanId, findings.page(scanId, true, after, size)))
        override suspend fun loadBefore(before: Long, size: Int) =
            slice(decodeStored(scanId, findings.pageBefore(scanId, true, before, size)))
    }

    companion object {
        private const val READ_BATCH = 500
        private const val PAGE_SIZE = 50
        private const val GROUP_PAGE_SIZE = 30
        const val CLOSED_SOURCE = "androdr_store"
        const val CLOSED_CATEGORY = "alert_closed"
        private const val MAX_CLOSED_LINES = 100
        private const val MAX_NOTE = 500
        private const val MAX_RULE = 64
        private const val MAX_VALUE = 128
    }
}

/** Keyset cursor of the open-alerts list: `(lastActivityAt, id)`, both descending. */
data class AlertCursor(val lastActivityAt: Long, val id: Long)

/** OPEN alerts, most recent activity first; observes `ScanResult`, `forensic_timeline` and `alert`. */
internal class OpenAlertPagingSource(db: AppDatabase) :
    KeysetPagingSource<AlertCursor, AlertView>(db, KeysetPagingSource.OBSERVED_TABLES) {
    private val dao = db.alertDao()

    override fun keyOf(item: AlertView) = AlertCursor(item.lastActivityAt, item.id)

    override suspend fun loadFrom(from: AlertCursor?, size: Int) = slice(
        if (from == null) {
            dao.openAfter(Long.MAX_VALUE, Long.MAX_VALUE, size)
        } else {
            dao.openAfter(from.lastActivityAt, from.id + 1, size)
        }.map(AlertView::of)
    )

    override suspend fun loadAfter(after: AlertCursor, size: Int) =
        slice(dao.openAfter(after.lastActivityAt, after.id, size).map(AlertView::of))

    override suspend fun loadBefore(before: AlertCursor, size: Int) =
        slice(dao.openBefore(before.lastActivityAt, before.id, size).map(AlertView::of))
}

/** Keyset cursor of the open-alert groups: `(lastActivityAt DESC, ruleId, matchedValue)`. */
data class AlertGroupCursor(val lastActivityAt: Long, val ruleId: String, val matchedValue: String)

/** OPEN-alert groups in list order, each with its newest alert; observes `alert` (and the other paged tables). */
internal class OpenAlertGroupPagingSource(db: AppDatabase) :
    KeysetPagingSource<AlertGroupCursor, AlertGroup>(db, KeysetPagingSource.OBSERVED_TABLES) {
    private val dao = db.alertDao()

    override fun keyOf(item: AlertGroup) = AlertGroupCursor(item.lastActivityAt, item.ruleId, item.matchedValue)

    override suspend fun loadFrom(from: AlertGroupCursor?, size: Int) = slice(
        withSamples(
            if (from == null) {
                dao.openGroupsAfter(Long.MAX_VALUE, "", "", size)
            } else {
                dao.openGroupsFrom(from.lastActivityAt, from.ruleId, from.matchedValue, size)
            }
        )
    )

    override suspend fun loadAfter(after: AlertGroupCursor, size: Int) =
        slice(withSamples(dao.openGroupsAfter(after.lastActivityAt, after.ruleId, after.matchedValue, size)))

    override suspend fun loadBefore(before: AlertGroupCursor, size: Int) =
        slice(withSamples(dao.openGroupsBefore(before.lastActivityAt, before.ruleId, before.matchedValue, size)))

    private suspend fun withSamples(rows: List<AlertGroupRow>): List<AlertGroup> {
        val samples = chunkedIn(rows.map { it.maxId }) { dao.alertsByIds(it) }.associateBy { it.id }
        return rows.map { r ->
            AlertGroup(
                r.ruleId, r.matchedValue, r.count, r.lastActivityAt, r.maxId, samples[r.maxId]?.let(AlertView::of),
            )
        }
    }
}
