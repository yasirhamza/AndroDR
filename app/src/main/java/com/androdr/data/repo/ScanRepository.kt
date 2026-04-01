package com.androdr.data.repo

import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.ScanResultDao
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ScanResult
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanRepository @Inject constructor(
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
     * Deletes DNS events with a [DnsEvent.timestamp] older than [cutoff].
     * Call periodically (e.g. from WorkManager) to keep the database lean.
     */
    suspend fun pruneOldDnsEvents(cutoff: Long) {
        dnsEventDao.deleteOlderThan(cutoff)
    }
}
