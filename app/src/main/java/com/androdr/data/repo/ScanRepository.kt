package com.androdr.data.repo

import androidx.annotation.VisibleForTesting
import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.ScanResultDao
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.ioc.IndicatorResolver
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.delay
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanRepository @Inject constructor(
    private val database: AppDatabase,
    private val scanResultDao: ScanResultDao,
    private val dnsEventDao: DnsEventDao,
    private val forensicTimelineEventDao: ForensicTimelineEventDao,
    private val indicatorResolver: IndicatorResolver,
    private val timelineRows: TimelineRowDeleter,
    private val scanWrites: ScanWriteRepository,
    private val scanLock: ScanLock,
) {

    // ── Scan results ───────────────────────────────────────────────────────────

    /** Emits the full scan history, newest first. */
    val allScans: Flow<List<ScanResult>> = scanResultDao.getAllScans()

    companion object {
        /** Selects the preferred scan: first with device flags (runtime), else latest. */
        fun List<ScanResult>.preferRuntimeScan(): ScanResult? =
            firstOrNull { it.deviceFlags.isNotEmpty() } ?: firstOrNull()

        /** How long a user delete waits for a retention or backfill batch to release the lock. */
        const val DELETE_LOCK_WAIT_MS = 2_000L
        private const val LOCK_POLL_MS = 25L
        private const val NANOS_PER_MILLI = 1_000_000L
    }

    /** Persists a completed [ScanResult] to the database. */
    suspend fun saveScan(scan: ScanResult) {
        scanResultDao.insert(scan)
    }

    /**
     * Atomically persists a completed scan along with all its timeline
     * events in a single Room transaction. Room's [InvalidationTracker]
     * fires one notification per transaction, so every Flow observing
     * `ScanResult` or `forensic_timeline` recomposes exactly once per
     * scan — instead of three times (scan insert + finding events insert
     * + usage stats delete+insert), which caused visible "timeline state
     * thrashing" during/after each scan.
     *
     * @param findingTimelineEvents events derived from SIGMA findings
     *   (runtime scan) or the bug-report analysis path. May be empty.
     * @param replaceUsageStatsEvents when non-null, the existing
     *   `source = "usage_stats"` rows are replaced with this list inside
     *   the same transaction. Pass `null` when usage stats are not
     *   relevant to this scan (e.g. bug-report analyses don't produce
     *   UsageStats timeline events).
     */
    suspend fun saveScanResults(
        scan: ScanResult,
        findingTimelineEvents: List<ForensicTimelineEvent>,
        replaceUsageStatsEvents: List<ForensicTimelineEvent>? = null
    ) {
        database.withTransaction {
            scanResultDao.insert(scan)
            if (findingTimelineEvents.isNotEmpty()) {
                forensicTimelineEventDao.insertAll(findingTimelineEvents)
            }
            if (replaceUsageStatsEvents != null) {
                timelineRows.bySource("usage_stats")
                if (replaceUsageStatsEvents.isNotEmpty()) {
                    forensicTimelineEventDao.insertAll(replaceUsageStatsEvents)
                }
            }
        }
    }

    /**
     * Like [saveScanResults] but runs a correlation pass *inside* the same
     * transaction, after raw events have been persisted and their
     * autoincrement IDs read back. This exists because [SigmaCorrelationEngine]
     * needs real [ForensicTimelineEvent.id] values on member events so that
     * each signal's `member_event_ids` references can be resolved by the
     * Timeline UI. Before this method existed, correlation ran on the pre-insert
     * events (all with `id = 0`) and every signal serialized `member_event_ids`
     * as a string of zeros, which broke the expand-cluster UI.
     *
     * Flow inside the transaction:
     *  1. Replace usage-stats events (if provided), then collect them with IDs.
     *  2. Insert [findingTimelineEvents] and collect them with assigned IDs.
     *  3. Call [correlator] with the union (findings + usage + lookback events
     *     the caller supplies). It returns signal rows to persist.
     *  4. Insert the returned signals.
     *  5. Ask [findingsForSignals] for the findings those signals become (#350).
     *  6. Insert [scan] LAST, carrying those findings, and return it. The scan
     *     row can go last because `forensic_timeline` declares no foreign key on
     *     `scanResultId` and [ScanResult.id] is assigned by the caller, so nothing
     *     above needs the row to exist first.
     *
     * @param correlator receives events-with-real-IDs (findings + replaced
     *   usage-stats, in that order) plus any [lookbackEvents] the caller passes
     *   in (already in the DB with their own IDs). It returns signal rows
     *   (`kind = "signal"`) to insert. The repo does the final insert.
     * @param lookbackEvents events already persisted from prior scans that
     *   should participate in this scan's correlation evaluation (e.g. the
     *   last 90 days of events for cross-scan chains).
     * @param preDelete optional cleanup run as the FIRST statement inside the
     *   transaction, before any insert. It exists so a caller that must delete
     *   rows before persisting the new scan (e.g. the intrusion-log import's
     *   replace-on-reimport sweep, #342) does so ATOMICALLY with the save: if
     *   the save then throws, Room rolls back the deletes too, so a failed
     *   persist can never leave the prior data destroyed and the new data
     *   unwritten. Default `null` ⇒ the live-scan and bug-report paths are
     *   unchanged (no pre-delete). Mirrors where the `usage_stats` delete runs.
     */
    suspend fun saveScanWithCorrelation(
        scan: ScanResult,
        findingTimelineEvents: List<ForensicTimelineEvent>,
        replaceUsageStatsEvents: List<ForensicTimelineEvent>? = null,
        lookbackEvents: List<ForensicTimelineEvent> = emptyList(),
        preDelete: (suspend () -> Unit)? = null,
        findingsForSignals: (List<ForensicTimelineEvent>) -> List<com.androdr.sigma.Finding> = { emptyList() },
        correlator: suspend (List<ForensicTimelineEvent>) -> List<ForensicTimelineEvent>
    ): ScanResult {
        return database.withTransaction {
            // Run any caller-supplied pre-delete FIRST and inside the tx, so a
            // subsequent insert failure rolls the deletes back with it (#342 B1).
            preDelete?.invoke()

            val persistedUsage: List<ForensicTimelineEvent> = if (replaceUsageStatsEvents != null) {
                timelineRows.bySource("usage_stats")
                if (replaceUsageStatsEvents.isEmpty()) emptyList()
                else assignIds(replaceUsageStatsEvents, forensicTimelineEventDao.insertAll(replaceUsageStatsEvents))
            } else emptyList()

            val persistedFindings: List<ForensicTimelineEvent> = if (findingTimelineEvents.isEmpty()) emptyList()
            else assignIds(findingTimelineEvents, forensicTimelineEventDao.insertAll(findingTimelineEvents))

            val signals = correlator(lookbackEvents + persistedFindings + persistedUsage)
            if (signals.isNotEmpty()) {
                forensicTimelineEventDao.insertAll(signals)
            }
            // The scan row goes LAST so it can carry the findings the correlation
            // pass produced (#350) -- one complete write, no update.
            val persisted =
                if (signals.isEmpty()) scan
                else scan.copy(findings = scan.findings + findingsForSignals(signals))
            scanResultDao.insert(persisted)
            persisted
        }
    }

    /**
     * Pairs each event in [inputs] with the corresponding Room autoincrement
     * ID from [ids] and returns copies with `id` populated. Drops entries
     * whose ID is `-1` (the OnConflictStrategy.IGNORE sentinel) so downstream
     * correlation doesn't reference rows that were skipped as duplicates.
     */
    private fun assignIds(
        inputs: List<ForensicTimelineEvent>,
        ids: List<Long>
    ): List<ForensicTimelineEvent> =
        inputs.zip(ids).mapNotNull { (event, id) ->
            if (id <= 0L) null else event.copy(id = id)
        }

    /**
     * Returns the two most recent [ScanResult] entries.
     * Useful for computing a delta between the last two scans.
     */
    suspend fun getLatestTwo(): List<ScanResult> = scanResultDao.getLatestTwo()

    // ── DNS events ─────────────────────────────────────────────────────────────

    /** Emits up to 200 most recent DNS events, newest first. */
    val recentDnsEvents: Flow<List<DnsEvent>> = dnsEventDao.getRecentEvents()

    /** Emits all DNS events that matched an IOC or blocklist, newest first. */
    val matchedDnsEvents: Flow<List<DnsEvent>> = dnsEventDao.getMatchedEvents()

    /** Records a single [DnsEvent] captured by the VPN layer. */
    suspend fun logDnsEvent(event: DnsEvent) {
        dnsEventDao.insert(event)
        // Also record matched DNS events in the forensic timeline
        if (event.reason != null) {
            runCatching { forensicTimelineEventDao.insert(event.toForensicTimelineEvent()) }
        }
    }

    /**
     * Batched DNS event insert. Used by the VPN packet path to amortize Room transaction
     * overhead — at typical browsing rates the per-query insert was the dominant battery
     * drain source. Matched events are also batched into the forensic timeline.
     *
     * Matched events are enriched here (off the VPN hot path) with real
     * family/severity/description metadata via [IndicatorResolver.resolveDomainRow],
     * looked up by the queried domain for EVERY matched event -- including
     * `blocklist` / `blocklist_detect` hits, whose reason string names no value. The
     * VPN bloom-filter path in `IndicatorResolver.isKnownBadDomain` returns a
     * stub `Indicator` with empty `campaign` / `severity = "UNKNOWN"` because
     * the bloom filter only stores the domain set, not the metadata. Without
     * enrichment, timeline rows end up with `campaignName = <domain>` and
     * `severity = "HIGH"` hard-coded from the reason string — which reads as
     * "0-38.com" being the campaign name, which it obviously isn't.
     */
    suspend fun logDnsEventsBatch(events: List<DnsEvent>) {
        if (events.isEmpty()) return
        dnsEventDao.insertAll(events)
        val matched = events.filter { it.reason != null }
        if (matched.isNotEmpty()) {
            runCatching {
                val enrichedRows = matched.map { dnsEvent ->
                    val indicator = runCatching { indicatorResolver.resolveDomainRow(dnsEvent.domain) }.getOrNull()
                    dnsEvent.toForensicTimelineEvent(indicator)
                }
                forensicTimelineEventDao.insertAll(enrichedRows)
            }
        }
    }

    /**
     * Deletes DNS events with a [DnsEvent.timestamp] older than [cutoff].
     * Call periodically (e.g. from WorkManager) to keep the database lean.
     */
    suspend fun pruneOldDnsEvents(cutoff: Long) {
        dnsEventDao.deleteOlderThan(cutoff)
    }

    /**
     * Deletes one scan (spec §5.1 Delete): `DELETING` first (Task D3 adds the audit row to that
     * transaction), then its own Timeline rows, its telemetry, and the `ScanResult` row last.
     * Returns false — deleting nothing — while a scan or import is running, or when the writer lock
     * stays busy past [DELETE_LOCK_WAIT_MS] ("A scan is running — try again when it finishes").
     */
    suspend fun deleteScan(scanId: Long): Boolean {
        underLockFirst { scanWrites.markForDelete(scanId) } ?: return false
        scanWrites.completeDelete(scanId)
        return true
    }

    /**
     * "Clear all": like [deleteScan] for every scan existing when it starts (a scan begun after its
     * first transaction survives); persistent audit rows survive.
     */
    suspend fun deleteAllScans(): Boolean {
        val ids = underLockFirst { scanWrites.markAllForDelete() } ?: return false
        scanWrites.completeDeleteAll(ids)
        return true
    }

    /** How long a user delete waits for the writer lock; tests shorten it. */
    @VisibleForTesting
    internal var deleteLockWaitMs: Long = DELETE_LOCK_WAIT_MS

    /**
     * Runs a delete's first transaction under the writer lock, taken outside any transaction.
     * Null (nothing run, lock not held) while a writer runs or when the lock stays busy.
     */
    private suspend fun <T : Any> underLockFirst(first: suspend () -> T): T? {
        if (scanLock.writerRunning.value) return null
        // writerRunning is raised only while the mutex is held, so holding it means no writer runs.
        if (!acquireLockWithin(deleteLockWaitMs)) return null
        try {
            return first()
        } finally {
            scanLock.mutex.unlock()
        }
    }

    /**
     * Polls [ScanLock.mutex] with `tryLock` until [waitMs] passes. Unlike a timed-out suspending
     * `lock()`, a poll can never acquire the lock and then report failure, so nothing leaks it.
     */
    private suspend fun acquireLockWithin(waitMs: Long): Boolean {
        val deadline = System.nanoTime() + waitMs * NANOS_PER_MILLI
        while (!scanLock.mutex.tryLock()) {
            if (System.nanoTime() >= deadline) return false
            delay(LOCK_POLL_MS)
        }
        return true
    }
}
