package com.androdr.data.repo

import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.ScanResultDao
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanRepository @Inject constructor(
    private val database: AppDatabase,
    private val scanResultDao: ScanResultDao,
    private val dnsEventDao: DnsEventDao,
    private val forensicTimelineEventDao: ForensicTimelineEventDao
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
     */
    suspend fun logDnsEventsBatch(events: List<DnsEvent>) {
        if (events.isEmpty()) return
        dnsEventDao.insertAll(events)
        val matched = events.filter { it.reason != null }
        if (matched.isNotEmpty()) {
            runCatching {
                forensicTimelineEventDao.insertAll(matched.map { it.toForensicTimelineEvent() })
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
