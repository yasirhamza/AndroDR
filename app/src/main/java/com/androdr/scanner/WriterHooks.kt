package com.androdr.scanner

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TimelineEvent
import com.androdr.data.model.UsageEvent
import com.androdr.data.repo.Correlation
import com.androdr.data.repo.FindingTotals
import com.androdr.data.repo.SessionHooks
import com.androdr.data.repo.TimelineRowDeleter
import com.androdr.data.store.AtomReader
import com.androdr.sigma.CorrelationBudget
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.IntrusionLogRecordBuilders
import com.androdr.sigma.LiveRecordBuilders
import com.androdr.sigma.NotStartedCause
import com.androdr.sigma.RuleCoverage
import com.androdr.sigma.SigmaCorrelationEngine
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.StoreRecord
import com.androdr.sigma.TaxonomyContract
import com.androdr.sigma.TimelineAtom
import com.androdr.sigma.TimelineCategories
import java.util.Collections

/** The correlation budget's clock: monotonic milliseconds (a wall-clock jump never cuts a pass short). */
internal fun monotonicMs(): Long = System.nanoTime() / NANOS_PER_MS

private const val NANOS_PER_MS = 1_000_000L

/**
 * What every writer adds to its session's finishing transaction in Phases A–C (spec §5.2): the
 * interim event rows ([interim], fed per chunk), the writer's detected-change or module rows
 * ([extraRows]), and the correlation pass over this scan's atoms — read after its rows were written,
 * plus [lookbackAtoms] for a live scan — under a [CorrelationBudget] ([newBudget]). Its chain
 * coverage gaps (#370) and budget cut-offs land on the summary.
 */
internal abstract class WriterHooks(
    protected val scan: ScanResult,
    private val engine: SigmaRuleEngine,
    private val correlationEngine: SigmaCorrelationEngine,
    private val newBudget: () -> CorrelationBudget = { CorrelationBudget(::monotonicMs) },
) : SessionHooks {
    val interim = InterimTimelineRows()

    /** Non-fatal problems the writer met; they land on the completed scan's `scannerErrors`. */
    val errors: MutableList<ScannerFailure> = Collections.synchronizedList(mutableListOf())

    // Only enabled rules contribute to correlation category propagation (and to the severity of
    // the findings the chains become, #350): a disabled rule's category must not influence
    // classifications when it produces no bindings.
    private val rules = engine.getCorrelationRules()
    private val atomRulesById = engine.getEnabledRules().associateBy { it.id }
    private var chainSkips: List<ScannerFailure> = emptyList()
    private var incompleteSkips: List<ScannerFailure> = emptyList()

    /** The session's finding totals, once [summarize] ran (counts past the intrusion-log cap). */
    var totals: FindingTotals? = null
        private set

    /**
     * Atoms already in the database that take part in this scan's correlation (live scans only).
     * An import correlates over its own atoms only, so its signals never reference live data.
     */
    protected open suspend fun lookbackAtoms(atoms: AtomReader, categories: Set<String>): List<TimelineAtom> =
        emptyList()

    /** Rows written before the interim rows (detected changes, bug-report module rows). */
    protected open fun extraRows(scan: ScanResult): List<ForensicTimelineEvent> = emptyList()

    override fun onChunk(
        service: String, source: TelemetrySource, chunk: List<StoreRecord>, firstOrdinal: Int,
        factIds: LongArray?, observed: BooleanArray?,
    ) = interim.onChunk(service, factIds, observed)

    override fun interimRows(scan: ScanResult): List<ForensicTimelineEvent> =
        extraRows(scan) + interim.rows(scan.id)

    /**
     * Inside the finishing transaction, after this scan's rows were inserted: this scan's own atoms
     * (its rows with their real ids, and the facts it observed) plus [lookbackAtoms], each ref once.
     * The budget's total deadline covers the reads, binding and grouping; a cut-off returns normally
     * with the signals already found and a CORRELATION_INCOMPLETE entry per affected rule.
     */
    override suspend fun correlate(scan: ScanResult, atoms: AtomReader): Correlation {
        val budget = newBudget()
        val atomCategoryByRuleId = engine.atomCategories()
        val categories = atomCategoryByRuleId.values.toSet()
        // Review m-2 / I-3: the one foreseeable, deterministic reason the atoms cannot be read is a
        // rule set binding more categories than one query holds. Checked before any read, and said
        // as such; every other read failure propagates and fails the finish honestly (a swallowed
        // SQLite error could leave a half-written scan marked COMPLETE).
        if (categories.size > AtomReader.MAX_ATOM_CATEGORIES) {
            incompleteSkips = correlationEngine.notStarted(rules, NotStartedCause.TOO_MANY_CATEGORIES)
            return Correlation.NONE
        }
        val all = (atoms.atomsForScan(scan.id, categories) + lookbackAtoms(atoms, categories)).distinctBy { it.ref }
        // #370: a chain rule fires only where every leg has events to bind to; legs with nothing
        // recorded are declared, so "no warning signs" never stands in for "not checked".
        chainSkips = RuleCoverage.noEventSkipsFor(rules, atomCategoryByRuleId, all)
        if (rules.isEmpty() || all.isEmpty()) return Correlation.NONE
        val bindings = engine.computeAtomBindings(all, budget::totalExpired)
        val result = correlationEngine.evaluate(rules, all, bindings, atomRulesById, budget)
        incompleteSkips = result.incomplete
        val signals = result.signals.map { it.copy(row = it.row.copy(scanResultId = scan.id)) }
        return if (signals.isEmpty()) {
            Correlation.NONE
        } else {
            Correlation(signals, correlationEngine.findingsFor(signals, rules, atomRulesById))
        }
    }

    override fun summarize(scan: ScanResult, totals: FindingTotals): ScanResult {
        this.totals = totals
        return scan.copy(
            knownMalwareCount = totals.knownMalware,
            scannerErrors = scan.scannerErrors + synchronized(errors) { errors.toList() } + chainSkips +
                incompleteSkips,
        )
    }

    /** [row] with the APK hash of its package from [hashByPkg] when the finding carried none. */
    protected fun withApkHash(row: ForensicTimelineEvent, hashByPkg: Map<String, String>): ForensicTimelineEvent =
        if (row.apkHash.isEmpty() && row.packageName.isNotEmpty()) {
            row.copy(apkHash = hashByPkg[row.packageName] ?: "")
        } else {
            row
        }
}

/**
 * The live scan: finding rows enriched with APK hashes, the detected-change rows (first-seen
 * installs, device-admin grants), the `usage_stats` rows of the re-read usage window replaced, a
 * correlation lookback ([lookbackAtoms]) that excludes every import source (#342 B2), and the
 * event watermarks this scan advances (spec §5.2).
 */
@Suppress("LongParameterList") // the live scan's inputs, built once by ScanOrchestrator
internal class LiveScanHooks(
    scan: ScanResult,
    engine: SigmaRuleEngine,
    correlationEngine: SigmaCorrelationEngine,
    private val timelineRows: TimelineRowDeleter,
    private val hashByPkg: Map<String, String>,
    private val detectedChanges: List<ForensicTimelineEvent>,
    private val lookbackWindowMs: Long,
    private val usage: UsageWindow,
    private val dns: DnsWindow,
    private val clock: () -> Long = System::currentTimeMillis,
    newBudget: () -> CorrelationBudget = { CorrelationBudget(::monotonicMs) },
) : WriterHooks(scan, engine, correlationEngine, newBudget) {
    init {
        interim.register<UsageEvent>(
            USAGE_STATS, cap = null, keepUnobserved = true, time = { it.timestamp },
        ) { e, scanId -> e.toForensicTimelineEvent(scanId) }
    }

    /** The DNS id this scan collected through; set once every row of [DnsWindow.range] was appended. */
    var dnsCollectedThrough: Long? = null

    /** A DNS read failed mid-stream: the DNS watermark stays put. */
    var dnsReadFailed = false

    /**
     * Whether this scan's usage rows replace earlier ones: only when usage was collected, and only
     * inside the re-read window `[since, until]`, where it writes a row for every event it read.
     * Rows outside it are kept: this scan cannot read their events. That includes rows stamped
     * after `until`, which exist when the device clock moved back since they were written.
     */
    private val replacesUsage = usage.collection is UsageCollection.Ok

    override suspend fun sweepPrior(scanId: Long) {
        if (replacesUsage) timelineRows.bySourceBetween(USAGE_STATS, usage.since, usage.until)
    }

    override fun watermarks(saveFallback: Boolean): Map<String, Long> = buildMap {
        Watermarks.nextTime(usage.previous, usage.collection, usage.until, clock(), saveFallback)
            ?.let { put(USAGE_STATS, it) }
        Watermarks.nextDnsId(dns.previous, dnsCollectedThrough, dns.failed || dnsReadFailed, saveFallback)
            ?.let { put(LiveRecordBuilders.DNS_MONITOR, it) }
    }

    override fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent =
        withApkHash(finding.toForensicTimelineEvent(scan), hashByPkg)

    override fun extraRows(scan: ScanResult): List<ForensicTimelineEvent> = detectedChanges

    /**
     * The correlation lookback (spec §5.2), read inside `finish` after this scan's rows were
     * inserted: visible live rows and facts a `COMPLETE` live scan observed, stamped in
     * `[scanStart - window, scanStart]`. Each guarantee is structural:
     *  - this scan's own rows and facts are not in it (its scan is still `IN_PROGRESS`, so neither
     *    [com.androdr.data.db.VisibleRow] nor a `COMPLETE` observation admits them) — they come
     *    once, from `atomsForScan`, and `correlate` also keeps each ref once;
     *  - the `usage_stats` rows `finish` replaces are gone: [sweepPrior] deleted them first in the
     *    same transaction, and the rows this scan wrote for those events are its own atoms;
     *  - nothing stamped after the scan start, and nothing an import recorded (#342 B2: imported
     *    events carry their own historical times; a signal they helped produce would be stamped
     *    with this live scan's id, unreachable by the import's sweep).
     */
    override suspend fun lookbackAtoms(atoms: AtomReader, categories: Set<String>): List<TimelineAtom> =
        if (lookbackWindowMs <= 0L) emptyList()
        else atoms.atomsBetween(scan.timestamp - lookbackWindowMs, scan.timestamp, categories)

    override fun summarize(scan: ScanResult, totals: FindingTotals): ScanResult = super.summarize(scan, totals).copy(
        riskySideloadCount = scan.findings.count {
            it.category == FindingCategory.APP_RISK && it.matchContext["is_sideloaded"] == "true"
        },
    )

    companion object {
        const val USAGE_STATS = "usage_stats"
    }
}

/**
 * An intrusion-log import: finding rows stamped with the import's source and their record's own
 * time, the capped newest-first DNS / connect / security rows (#342 B3/B4), and the
 * replace-on-reimport sweep of every prior import ([deletePriorIntrusionLogRows]).
 */
internal class IntrusionLogHooks(
    scan: ScanResult,
    engine: SigmaRuleEngine,
    correlationEngine: SigmaCorrelationEngine,
    private val timeline: ForensicTimelineEventDao,
    private val timelineRows: TimelineRowDeleter,
) : WriterHooks(scan, engine, correlationEngine) {
    init {
        interim.register<ImportedDnsEvent>(
            IntrusionLogRecordBuilders.DNS_MONITOR, ScanOrchestrator.DNS_PERSIST_CAP, keepUnobserved = false,
            time = { it.event.timestamp },
        ) { e, scanId -> e.toForensicTimelineEvent(scanId) }
        interim.register<NetworkTelemetry>(
            IntrusionLogRecordBuilders.NETWORK_MONITOR, ScanOrchestrator.CONNECT_PERSIST_CAP, keepUnobserved = false,
            time = { it.timestamp },
        ) { e, scanId -> e.toForensicTimelineEvent(scanId) }
        interim.register<SecurityLogEvent>(
            IntrusionLogRecordBuilders.SECURITY_LOG, ScanOrchestrator.SECURITY_PERSIST_CAP, keepUnobserved = false,
            time = { it.timestamp },
        ) { e, scanId -> e.toForensicTimelineEvent(scanId) }
    }

    override suspend fun sweepPrior(scanId: Long) = deletePriorIntrusionLogRows(scanId)

    override fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent =
        finding.toForensicTimelineEvent(scan, isBugreport = true).copy(
            source = "intrusion_log_analysis",
            telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT,
            // The DNS/network/security field maps carry "timestamp" and the evaluator copies scalar
            // record fields into matchContext as strings, so a finding inherits its own event's
            // time. A finding without one falls back to 0L, which the Timeline renders as "Unknown".
            startTimestamp = FindingRank.eventTimeMs(finding)
        )

    /**
     * Replace-on-reimport sweep (#342 spec §4.2; Phases A–C, forensic rows only): removes every
     * Timeline row a previous intrusion-log import left behind, as the first statement of the
     * finishing transaction, so a failed finish rolls it back. [currentScanId] is excluded.
     *
     * Deleting by source alone is not enough. The correlation engine persists its signals with
     * `source = "sigma_correlation_engine"` (shared with the live-scan and bug-report paths, so that
     * source must never be deleted wholesale) and each signal's `signal_member` rows point at the
     * raw rows that produced it. Every row of one import — raw, finding, and signal — carries that
     * import's `scanResultId`, so the ids owning "intrusion_log" rows identify the whole set. The
     * two source deletes still run afterwards as belt-and-braces for rows written without a scan id.
     * The prior imports' facts and observations stay in the store until their scans are deleted.
     */
    private suspend fun deletePriorIntrusionLogRows(currentScanId: Long) {
        timeline.getDistinctScanIdsBySource("intrusion_log").filter { it != currentScanId }.forEach { priorScanId ->
            timelineRows.byScanId(priorScanId)
        }
        timelineRows.bySource("intrusion_log")
        timelineRows.bySource("intrusion_log_analysis")
    }
}

/**
 * A bug-report import: finding rows enriched with APK hashes, then the modules' raw timeline rows
 * not already covered by a finding row at the same (package, time) — so a finding and its raw
 * evidence don't read as duplicates — and the modules' own rows (e.g. install times).
 *
 * Ruling R17: a module row and the fact it was parsed from must never bind twice in correlation.
 * Each module row carries the `recordId` of its fact, matched by (category, package, event time)
 * against the facts this import stored ([onChunk]), one fact per row; the atom reader then leaves
 * that fact out, because the row stands in for it.
 */
internal class BugReportHooks(
    scan: ScanResult,
    engine: SigmaRuleEngine,
    correlationEngine: SigmaCorrelationEngine,
    private val hashByPkg: Map<String, String>,
    private val moduleTimeline: List<TimelineEvent>,
    private val moduleRows: List<ForensicTimelineEvent>,
    newBudget: () -> CorrelationBudget = { CorrelationBudget(::monotonicMs) },
) : WriterHooks(scan, engine, correlationEngine, newBudget) {
    private val coveredByFinding = HashSet<Pair<String, Long>>()

    private data class EventKey(val category: String, val packageName: String, val time: Long)

    /** The keys module rows have, so only facts a row can claim are remembered. */
    private val moduleKeys: Set<EventKey> by lazy {
        moduleTimeline.mapTo(HashSet()) { EventKey(it.category, it.packageName.orEmpty(), it.timestamp) } +
            moduleRows.map { EventKey(it.category, it.packageName, it.startTimestamp) }
    }

    /** Stored facts by key, in store order; each module row claims (removes) one. */
    private val factsByKey = HashMap<EventKey, ArrayDeque<Long>>()

    override fun onChunk(
        service: String, source: TelemetrySource, chunk: List<StoreRecord>, firstOrdinal: Int,
        factIds: LongArray?, observed: BooleanArray?,
    ) {
        super.onChunk(service, source, chunk, firstOrdinal, factIds, observed)
        if (factIds == null) return
        val packageField = TaxonomyContract.packageField(service)
        chunk.forEachIndexed { i, record ->
            val time = TaxonomyContract.eventTimeOf(service, record.fields) ?: return@forEachIndexed
            val pkg = packageField?.let { record.fields[it]?.toString() }.orEmpty()
            val key = EventKey(TimelineCategories.categoryOf(service, record.fields), pkg, time)
            if (key in moduleKeys) factsByKey.getOrPut(key) { ArrayDeque() }.addLast(factIds[i])
        }
    }

    private fun claim(category: String, packageName: String, time: Long): Long? =
        factsByKey[EventKey(category, packageName, time)]?.removeFirstOrNull()

    override fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent {
        val row = withApkHash(finding.toForensicTimelineEvent(scan, isBugreport = true), hashByPkg)
        if (row.startTimestamp > 0L && row.packageName.isNotEmpty()) {
            coveredByFinding += row.packageName to row.startTimestamp
        }
        return row
    }

    /** Called after every [findingRow] of the finishing transaction. */
    override fun extraRows(scan: ScanResult): List<ForensicTimelineEvent> =
        moduleTimeline
            .filterNot { raw -> raw.packageName != null && (raw.packageName to raw.timestamp) in coveredByFinding }
            .map { raw ->
                raw.toForensicTimelineEvent(scan.id)
                    .copy(recordId = claim(raw.category, raw.packageName.orEmpty(), raw.timestamp))
            } +
            moduleRows.map {
                it.copy(scanResultId = scan.id, recordId = claim(it.category, it.packageName, it.startTimestamp))
            }
}

/**
 * Appends each intrusion-log chunk to the writer [session], staging its typed records in [interim]
 * first so the session's `onChunk` can pair them with their fact ids.
 */
internal class IntrusionLogSessionChunks(
    private val session: ChunkedScanWriter.Session,
    private val interim: InterimTimelineRows,
    private val fallbackCapturedAt: Long,
) : IntrusionLogChunks {
    override suspend fun dns(events: List<ImportedDnsEvent>, records: List<StoreRecord>) =
        put(IntrusionLogRecordBuilders.DNS_MONITOR, events, records)

    override suspend fun connect(events: List<NetworkTelemetry>, records: List<StoreRecord>) =
        put(IntrusionLogRecordBuilders.NETWORK_MONITOR, events, records)

    override suspend fun security(events: List<SecurityLogEvent>, records: List<StoreRecord>) =
        put(IntrusionLogRecordBuilders.SECURITY_LOG, events, records)

    private suspend fun <T> put(service: String, events: List<T>, records: List<StoreRecord>) {
        interim.stage(service, events)
        val capturedAt = capturedAtOf(records, fallbackCapturedAt)
        session.append(service, TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt, records)
    }
}

/**
 * The `captured_at` the records of one append share (their first record's), so the store strips it
 * from their bodies; [fallback] when the records carry none.
 */
internal fun capturedAtOf(records: List<StoreRecord>, fallback: Long): Long =
    (records.firstOrNull()?.fields?.get("captured_at") as? Long) ?: fallback
