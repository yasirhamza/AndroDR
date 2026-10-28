package com.androdr.data.store

import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.ObservationRow
import com.androdr.data.db.chunkedEach
import com.androdr.data.model.TelemetryState
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.SettingsRepository
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * What one [TelemetryRetention.run] did: [completed] is false when a scan or import held `scanMutex`
 * and the cycle stopped early (the next cycle starts again from the newest scan).
 */
data class RetentionOutcome(val completed: Boolean, val observationsRemoved: Long)

/**
 * Retention (spec §5.1 Retention), run by `IocUpdateWorker` after the IOC fetch:
 * - **snapshot observations** are kept for the newest N `COMPLETE` live scans
 *   ([SettingsRepository.snapshotRetentionScans], default 20);
 * - **live event observations** are kept for [LIVE_EVENT_RETENTION_MS] (30 days, by event time);
 * - **import observations** are never touched (only live scans are walked);
 * - **pinned facts** are always kept: a batch removes only facts left with no observation and no pin
 *   ([TelemetryStore.releaseUnpinned], the shared `PinnedFact` fragment), so a pinned fact becomes a
 *   pinned orphan that `TelemetryReader` still decodes from its `first*` envelope.
 *
 * Each batch takes `scanMutex.tryLock()` outside its Room transaction; when the lock is held the cycle
 * stops. Each batch is one transaction: delete its observations, then its candidate facts that now
 * have no observation and no pin, then bodies no fact uses, and mark the scan `PARTIAL_RETENTION` (or,
 * for a `FAILED` scan, `FAILED_PARTIAL_RETENTION`, which keeps the failure). So a kill between batches
 * leaves no unpinned orphan (S3). A batch that throws sets [StoreDirtyFlag] and rethrows.
 */
@Singleton
class TelemetryRetention @Inject constructor(
    private val db: AppDatabase,
    private val store: TelemetryStore,
    private val lock: ScanLock,
    private val dirty: StoreDirtyFlag,
    private val settings: SettingsRepository,
) {
    /** Which observations a batch removes: old live events, or (beyond the newest N scans) snapshots. */
    enum class Phase { EVENTS, SNAPSHOTS }

    private val scans get() = db.scanResultDao()
    private val observations get() = db.scanObservationDao()

    /**
     * One retention cycle at time [now]. Walks the `COMPLETE` live scans newest first by keyset; a
     * scan that completes meanwhile can only shift older scans' ranks down, which keeps more; a deleted newer scan
     * would shift them up, so a candidate's rank is re-read before its snapshots are trimmed.
     */
    suspend fun run(now: Long = System.currentTimeMillis()): RetentionOutcome {
        val keep = settings.snapshotRetentionScans.first()
        val eventCutoff = now - LIVE_EVENT_RETENTION_MS
        var removed = 0L
        var rank = 0
        var afterTimestamp = Long.MAX_VALUE
        var afterId = Long.MAX_VALUE
        while (true) {
            val page = scans.liveKeysAfter(afterTimestamp, afterId, SCAN_PAGE)
            if (page.isEmpty()) break
            for (scan in page) {
                val beyondKeep = rank++ >= keep
                removed += drain(scan.id, Phase.EVENTS, eventCutoff) ?: return RetentionOutcome(false, removed)
                // The walk's rank only grows stale upwards if a newer scan was deleted meanwhile, so a
                // candidate's rank is re-read before its snapshots go (review m4).
                if (beyondKeep && scans.liveNewerThan(scan.timestamp, scan.id) >= keep) {
                    removed += drain(scan.id, Phase.SNAPSHOTS, eventCutoff) ?: return RetentionOutcome(false, removed)
                }
            }
            afterTimestamp = page.last().timestamp
            afterId = page.last().id
        }
        return RetentionOutcome(true, removed)
    }

    /** Runs [phase]'s batches for [scanId] until none is left; null when `scanMutex` was held. */
    private suspend fun drain(scanId: Long, phase: Phase, cutoff: Long): Long? {
        var total = 0L
        while (true) {
            val n = try {
                batch(scanId, phase, cutoff)
            } catch (@Suppress("TooGenericExceptionCaught") e: Exception) {
                withContext(NonCancellable) { dirty.set() }
                throw e
            } ?: return null
            if (n == 0) return total
            total += n
        }
    }

    /**
     * One batch of at most [BATCH] observations of [scanId] in one transaction, under
     * `scanMutex.tryLock()` (taken outside the transaction). Returns how many were removed, or null
     * when the lock was held.
     */
    internal suspend fun batch(scanId: Long, phase: Phase, cutoff: Long): Int? {
        if (!lock.mutex.tryLock()) return null
        try {
            return db.withTransaction {
                // A scan the user marked DELETING after the walk read it is left to its delete, which
                // releases the facts its findings pin only once it knows its observations (D4 fix).
                if (!scans.isComplete(scanId)) return@withTransaction 0
                val rows: List<ObservationRow> = when (phase) {
                    Phase.EVENTS -> observations.retentionEventBatch(scanId, cutoff, BATCH)
                    Phase.SNAPSHOTS -> observations.retentionSnapshotBatch(scanId, BATCH)
                }
                if (rows.isNotEmpty()) {
                    chunkedEach(rows.map { it.rowId }) { observations.deleteRows(it) }
                    store.releaseUnpinned(rows.map { it.recordId })
                    scans.setTelemetryState(scanId, TelemetryState.PARTIAL_RETENTION, TelemetryState.STORED)
                    scans.setTelemetryState(scanId, TelemetryState.FAILED_PARTIAL_RETENTION, TelemetryState.FAILED)
                }
                rows.size
            }
        } finally {
            lock.mutex.unlock()
        }
    }

    companion object {
        /** Observations per retention transaction. */
        const val BATCH = 500

        /** Live event observations are kept this long, by event time (spec §5.1). */
        const val LIVE_EVENT_RETENTION_MS = 30L * 24 * 60 * 60 * 1000

        private const val SCAN_PAGE = 200
    }
}
