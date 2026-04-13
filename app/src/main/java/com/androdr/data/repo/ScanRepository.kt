package com.androdr.data.repo

import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.IndicatorDao
import com.androdr.data.db.ScanResultDao
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.Indicator
import com.androdr.data.model.ScanResult
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanRepository @Inject constructor(
    private val database: AppDatabase,
    private val scanResultDao: ScanResultDao,
    private val dnsEventDao: DnsEventDao,
    private val forensicTimelineEventDao: ForensicTimelineEventDao,
    private val indicatorDao: IndicatorDao
) {

    // ── Scan results ───────────────────────────────────────────────────────────

    /** Emits the full scan history, newest first. */
    val allScans: Flow<List<ScanResult>> = scanResultDao.getAllScans()

    companion object {
        /** Selects the preferred scan: first with device flags (runtime), else latest. */
        fun List<ScanResult>.preferRuntimeScan(): ScanResult? =
            firstOrNull { it.deviceFlags.isNotEmpty() } ?: firstOrNull()
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
                forensicTimelineEventDao.deleteBySource("usage_stats")
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
     *  1. Insert [scan].
     *  2. Replace usage-stats events (if provided), then collect them with IDs.
     *  3. Insert [findingTimelineEvents] and collect them with assigned IDs.
     *  4. Call [correlator] with the union (findings + usage + lookback events
     *     the caller supplies). It returns signal rows to persist.
     *  5. Insert the returned signals.
     *
     * @param correlator receives events-with-real-IDs (findings + replaced
     *   usage-stats, in that order) plus any [lookbackEvents] the caller passes
     *   in (already in the DB with their own IDs). It returns signal rows
     *   (`kind = "signal"`) to insert. The repo does the final insert.
     * @param lookbackEvents events already persisted from prior scans that
     *   should participate in this scan's correlation evaluation (e.g. the
     *   last 90 days of events for cross-scan chains).
     */
    suspend fun saveScanWithCorrelation(
        scan: ScanResult,
        findingTimelineEvents: List<ForensicTimelineEvent>,
        replaceUsageStatsEvents: List<ForensicTimelineEvent>? = null,
        lookbackEvents: List<ForensicTimelineEvent> = emptyList(),
        correlator: suspend (List<ForensicTimelineEvent>) -> List<ForensicTimelineEvent>
    ) {
        database.withTransaction {
            scanResultDao.insert(scan)

            val persistedUsage: List<ForensicTimelineEvent> = if (replaceUsageStatsEvents != null) {
                forensicTimelineEventDao.deleteBySource("usage_stats")
                if (replaceUsageStatsEvents.isEmpty()) emptyList()
                else assignIds(replaceUsageStatsEvents, forensicTimelineEventDao.insertAll(replaceUsageStatsEvents))
            } else emptyList()

            val persistedFindings: List<ForensicTimelineEvent> = if (findingTimelineEvents.isEmpty()) emptyList()
            else assignIds(findingTimelineEvents, forensicTimelineEventDao.insertAll(findingTimelineEvents))

            val signals = correlator(lookbackEvents + persistedFindings + persistedUsage)
            if (signals.isNotEmpty()) {
                forensicTimelineEventDao.insertAll(signals)
            }
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
     * campaign/severity/description metadata via `indicatorDao.lookup`. The
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
                    val lookupKey = extractMatchedValue(dnsEvent.reason)
                    val indicator: Indicator? = lookupKey?.let { key ->
                        runCatching { indicatorDao.lookup("domain", key) }.getOrNull()
                    }
                    dnsEvent.toForensicTimelineEvent(indicator)
                }
                forensicTimelineEventDao.insertAll(enrichedRows)
            }
        }
    }

    /** Parses "IOC: <val>" / "IOC_detect: <val>" reason strings to extract the matched value. */
    private fun extractMatchedValue(reason: String?): String? = when {
        reason == null -> null
        reason.startsWith("IOC_detect: ") -> reason.removePrefix("IOC_detect: ")
        reason.startsWith("IOC: ") -> reason.removePrefix("IOC: ")
        else -> null
    }

    /**
     * Deletes DNS events with a [DnsEvent.timestamp] older than [cutoff].
     * Call periodically (e.g. from WorkManager) to keep the database lean.
     */
    suspend fun pruneOldDnsEvents(cutoff: Long) {
        dnsEventDao.deleteOlderThan(cutoff)
    }

    suspend fun deleteScan(scanId: Long) {
        // Single transaction so the History screen and Timeline screen
        // both receive exactly one invalidation after the scan is gone,
        // instead of rendering a half-deleted intermediate state between
        // the timeline-event delete and the scan-row delete.
        database.withTransaction {
            forensicTimelineEventDao.deleteByScanId(scanId)
            scanResultDao.deleteById(scanId)
        }
    }

    suspend fun deleteAllScans() {
        database.withTransaction {
            forensicTimelineEventDao.deleteAll()
            scanResultDao.deleteAll()
        }
    }
}
