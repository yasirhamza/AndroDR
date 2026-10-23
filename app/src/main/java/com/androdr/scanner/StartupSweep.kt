package com.androdr.scanner

import com.androdr.data.db.SweepTarget
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.ScanWriteRepository
import com.androdr.data.store.StoreDirtyFlag
import com.androdr.data.store.TelemetryStore
import kotlinx.coroutines.sync.withLock
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Finishes what a killed process left (spec §5.2 Failure handling): removes every `IN_PROGRESS`
 * (killed writer) and `DELETING` (interrupted delete) scan, then garbage-collects the store when
 * it swept something or the dirty flag is set.
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
) {
    /** Returns how many scans it removed. */
    suspend fun run(): Int {
        val targets = lock.mutex.withLock { repo.sweepTargets() }
        for (target in targets) {
            val interrupted = interruptedRow(target)
            if (interrupted != null) repo.markForDelete(target.id, interrupted)
            repo.completeDelete(target.id)
        }
        if (targets.isNotEmpty() || dirty.isSet()) store.gcUnobservedUnpinned()
        return targets.size
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
        const val SOURCE = "androdr_store"
        const val CATEGORY = "import_interrupted"
    }
}
