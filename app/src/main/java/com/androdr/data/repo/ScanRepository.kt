package com.androdr.data.repo

import androidx.annotation.VisibleForTesting
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.ScanResultDao
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.store.HashKeys
import com.androdr.data.store.KeysetPagingSource
import com.androdr.data.store.tableChanges
import com.androdr.ioc.IndicatorResolver
import com.androdr.sigma.LiveRecordBuilders
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.delay
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanRepository @Inject constructor(
    private val scanResultDao: ScanResultDao,
    private val dnsEventDao: DnsEventDao,
    private val forensicTimelineEventDao: ForensicTimelineEventDao,
    private val indicatorResolver: IndicatorResolver,
    private val scanWrites: ScanWriteRepository,
    private val scanLock: ScanLock,
    private val db: AppDatabase,
) {

    // ── Scan results ───────────────────────────────────────────────────────────

    /**
     * The scan history, newest first, keyset-paged on `timestamp` (spec §5.5: no capped list);
     * re-pages when a scan completes or is deleted.
     */
    fun pagedScans(): Flow<PagingData<ScanResult>> =
        Pager(PagingConfig(pageSize = SCAN_PAGE_SIZE, enablePlaceholders = false)) {
            ScanPagingSource(db, scanResultDao)
        }.flow

    /** True while at least one scan is listed (History's empty state). */
    val hasScans: Flow<Boolean> = scanResultDao.anyComplete()

    /** The newest COMPLETE live scan (null before the first one). */
    val latestLiveScan: Flow<ScanResult?> = scanResultDao.latestLive()

    /** The two newest COMPLETE scans (the Dashboard's diff), re-read when scans change. */
    val latestTwo: Flow<List<ScanResult>> = db.tableChanges(arrayOf("ScanResult"))
        .map { scanResultDao.getLatestTwo() }
        .flowOn(Dispatchers.IO)

    /** The two newest COMPLETE live scans (the Dashboard's diff, spec §5.4), re-read when scans change. */
    val latestTwoLive: Flow<List<ScanResult>> = db.tableChanges(arrayOf("ScanResult"))
        .map { scanResultDao.livePagedAfter(Long.MAX_VALUE, 2) }
        .flowOn(Dispatchers.IO)

    /** Whether scan [id] is saved (COMPLETE). */
    suspend fun isSaved(id: Long): Boolean = scanResultDao.completeById(id) != null

    /** The COMPLETE scan listed just before [scan] (History's diff baseline), if any. */
    suspend fun previousOf(scan: ScanResult): ScanResult? = scanResultDao.previousOf(scan.timestamp).firstOrNull()

    companion object {
        private const val SCAN_PAGE_SIZE = 30

        /** How long a user delete waits for a retention or backfill batch to release the lock. */
        const val DELETE_LOCK_WAIT_MS = 2_000L
        private const val LOCK_POLL_MS = 25L
        private const val NANOS_PER_MILLI = 1_000_000L
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

    /**
     * Records a single [DnsEvent] captured by the VPN layer. A matched event's Timeline row carries
     * `sourceEventKey = h128("dns:$id")`, the key of the live DNS fact a scan stores for it.
     */
    suspend fun logDnsEvent(event: DnsEvent) {
        val id = dnsEventDao.insert(event)
        // Also record matched DNS events in the forensic timeline
        if (event.reason != null) {
            runCatching {
                forensicTimelineEventDao.insert(event.toForensicTimelineEvent(null, dnsRowKey(id)))
            }
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
    suspend fun logDnsEventsBatch(events: List<DnsEvent>): List<Long> {
        if (events.isEmpty()) return emptyList()
        val ids = dnsEventDao.insertAll(events)
        val matched = events.indices.filter { events[it].reason != null }
        if (matched.isNotEmpty()) {
            runCatching {
                val enrichedRows = matched.map { i ->
                    val dnsEvent = events[i]
                    val indicator = runCatching { indicatorResolver.resolveDomainRow(dnsEvent.domain) }.getOrNull()
                    dnsEvent.toForensicTimelineEvent(indicator, ids.getOrNull(i)?.let(::dnsRowKey))
                }
                forensicTimelineEventDao.insertAll(enrichedRows)
            }
        }
        return ids
    }

    /** h128 of the live DNS fact's source event key for DnsEvent row [id] (spec §5.2). */
    private fun dnsRowKey(id: Long): ByteArray = HashKeys.h128(LiveRecordBuilders.dnsSourceKey(id))

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

/** A scan list position: `(timestamp, id)`, newest first. */
data class ScanCursor(val timestamp: Long, val id: Long)

/**
 * COMPLETE scans newest first, keyset on `(timestamp, id)` ([ScanResultDao.pagedAfter]), so equal
 * timestamps never lose a scan at a page boundary. Observes `ScanResult`.
 */
internal class ScanPagingSource(db: AppDatabase, private val dao: ScanResultDao) :
    KeysetPagingSource<ScanCursor, ScanResult>(db, KeysetPagingSource.OBSERVED_TABLES) {
    override fun keyOf(item: ScanResult) = ScanCursor(item.timestamp, item.id)

    // The refresh key is inclusive: start just past it in descending order (same timestamp, id + 1).
    override suspend fun loadFrom(from: ScanCursor?, size: Int) = slice(
        if (from == null) dao.pagedAfter(Long.MAX_VALUE, Long.MAX_VALUE, size)
        else dao.pagedAfter(from.timestamp, from.id + 1, size)
    )

    override suspend fun loadAfter(after: ScanCursor, size: Int) =
        slice(dao.pagedAfter(after.timestamp, after.id, size))

    override suspend fun loadBefore(before: ScanCursor, size: Int) =
        slice(dao.pagedBefore(before.timestamp, before.id, size))
}
