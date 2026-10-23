package com.androdr.scanner

import android.util.Log
import com.androdr.data.db.LegacyEventRowCleanup
import com.androdr.data.db.SignalMemberBackfill
import com.androdr.data.db.SweepTarget
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.ScanWriteRepository
import com.androdr.data.store.StoreDirtyFlag
import com.androdr.data.store.TelemetryStore
import com.androdr.reporting.ReportFiles
import kotlinx.coroutines.sync.withLock
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Finishes what a killed process left (spec §5.2 Failure handling): removes every `IN_PROGRESS`
 * (killed writer) and `DELETING` (interrupted delete) scan, then garbage-collects the store when
 * it swept something or the dirty flag is set, and runs the one-time [SignalMemberBackfill] and
 * [LegacyEventRowCleanup].
 *
 * [ScanLock.mutex] is held only to snapshot the ids, so a scan started meanwhile is never in the
 * snapshot and survives. A swept `IN_PROGRESS` import gets one persistent "import interrupted"
 * row, written in the same transaction that marks it `DELETING` (a resumed sweep sees `DELETING`
 * and writes no second one; a `DELETING` scan already has its audit row).
 */
@Singleton
class StartupSweep @Inject constructor(
    private val lock: ScanLock,
    private val repo: ScanWriteRepository,
    private val store: TelemetryStore,
    private val dirty: StoreDirtyFlag,
    private val reportFiles: ReportFiles,
    private val backfill: SignalMemberBackfill,
    private val legacyRows: LegacyEventRowCleanup,
) {
    /**
     * Returns how many scans it removed. A target that fails is logged, sets [StoreDirtyFlag] and
     * is left for the next start; the other targets still go.
     */
    suspend fun run(): Int {
        val targets = lock.mutex.withLock { repo.sweepTargets() }
        var removed = 0
        for (target in targets) {
            try {
                sweep(target)
                removed++
            } catch (@Suppress("TooGenericExceptionCaught") e: Exception) {
                Log.e(TAG, "Startup sweep could not remove scan ${target.id}", e)
                dirty.set()
            }
        }
        if (targets.isNotEmpty() || dirty.isSet()) store.gcUnobservedUnpinned()
        runCatching { reportFiles.deleteStale() }.onFailure { Log.w(TAG, "Stale report cleanup failed", it) }
        // One-time move of legacy signals' member lists into signal_member (spec §5.4); it takes the
        // lock per batch, and a failure is retried next launch.
        runCatching { backfill.run() }.onFailure { Log.w(TAG, "Signal member backfill failed", it) }
        // One-time removal of the retired event adapters' rows (C3, spec §5.3), only once the backfill
        // has finished: until then a legacy signal's list is not in signal_member and would protect
        // nothing (review m1). A pending backfill defers the cleanup to a later launch.
        runCatching { if (backfill.isDone()) legacyRows.run() }
            .onFailure { Log.w(TAG, "Legacy event-row cleanup failed", it) }
        return removed
    }

    private suspend fun sweep(target: SweepTarget) {
        val interrupted = interruptedRow(target)
        if (interrupted != null) repo.markForDelete(target.id, interrupted)
        repo.completeDelete(target.id)
    }

    private fun interruptedRow(target: SweepTarget): ForensicTimelineEvent? {
        if (target.state != ScanState.IN_PROGRESS || target.source == TelemetrySource.LIVE_SCAN) return null
        val what = if (target.source == TelemetrySource.BUGREPORT_IMPORT) "Bug report" else "Intrusion log"
        return ForensicTimelineEvent(
            startTimestamp = target.timestamp,
            source = SOURCE,
            category = CATEGORY,
            description = "$what import interrupted",
            details = "The app stopped before this import finished; nothing from it was kept. Import it again.",
            telemetrySource = target.source,
            persistent = true,
        )
    }

    companion object {
        private const val TAG = "StartupSweep"
        const val SOURCE = "androdr_store"
        const val CATEGORY = "import_interrupted"
    }
}
