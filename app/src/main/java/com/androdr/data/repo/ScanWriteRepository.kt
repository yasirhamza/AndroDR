package com.androdr.data.repo

import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.RuleRecord
import com.androdr.data.db.SweepTarget
import com.androdr.data.db.chunkedIn
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetryState
import com.androdr.data.store.TelemetryStore
import com.androdr.scanner.KeptFinding
import com.androdr.scanner.SessionHooks
import javax.inject.Inject
import javax.inject.Singleton

/** The guarded finish found the scan no longer `IN_PROGRESS` (deleted or marked `DELETING` meanwhile). */
class ScanNotInProgressException(scanId: Long) : IllegalStateException("scan $scanId is no longer IN_PROGRESS")

/**
 * The writer session's and the scan deleters' transactions (spec §5.1 Delete, §5.2), split out of
 * [ScanRepository]. Never takes `ScanLock`: callers hold it as the spec requires (the session
 * through `ScanLock.withWriter`, user deletes for [markForDelete] only, the sweep for its snapshot).
 */
@Singleton
class ScanWriteRepository @Inject constructor(
    private val db: AppDatabase,
    private val store: TelemetryStore,
    private val rows: TimelineRowDeleter,
) {
    private val scans get() = db.scanResultDao()
    private val writes get() = db.scanWriteDao()
    private val timeline get() = db.forensicTimelineEventDao()

    /** Opens a session's scan, hidden until [finish]. */
    suspend fun begin(scan: ScanResult) = scans.insertInProgress(scan)

    /**
     * The session's single finishing transaction (spec §5.2 step 5, Phases A–C): the prior-import
     * sweep, this scan's finding rows (with `level` and `recordId`), the interim event rows, then the
     * guarded `IN_PROGRESS → COMPLETE` update and the summary columns. Throws — rolling everything
     * back — with [ScanNotInProgressException] when the guard changes no row.
     */
    suspend fun finish(
        scan: ScanResult, kept: List<KeptFinding>, hooks: SessionHooks, telemetryState: TelemetryState,
    ): ScanResult = db.withTransaction {
        hooks.sweepPrior(scan.id)
        val findingRows = kept.filter { it.finding.triggered }.map { k ->
            val row = hooks.findingRow(k.finding, scan)
            check(row.level == k.finding.level) { "finding row for ${k.finding.ruleId} must carry its level" }
            row.copy(recordId = k.recordId, scanResultId = scan.id)
        }
        if (findingRows.isNotEmpty()) timeline.insertAll(findingRows)
        val interim = hooks.interimRows(scan)
        if (interim.isNotEmpty()) timeline.insertAll(interim)
        if (scans.complete(scan.id, telemetryState) == 0) throw ScanNotInProgressException(scan.id)
        val completed = hooks.summarize(scan.copy(findings = kept.map { it.finding }))
            .copy(id = scan.id, state = ScanState.COMPLETE, telemetryState = telemetryState)
        writes.update(completed)
        completed
    }

    /**
     * Of [recordIds], the `(ruleId, recordId)` pairs a visible finding row already carries (the
     * Phase A–C stand-in for "an alert with this record key exists", spec §5.2 Late-IOC re-check).
     */
    suspend fun existingFindings(recordIds: Collection<Long>): Set<RuleRecord> =
        chunkedIn(recordIds) { timeline.findingRuleRecords(it) }.toHashSet()

    /**
     * First delete step, one transaction: hide [scanId] (`DELETING`) and write [persistentRow] if
     * given — the "import interrupted" row from the sweep, or (Task D3) the deletion audit row.
     */
    suspend fun markForDelete(scanId: Long, persistentRow: ForensicTimelineEvent? = null) = db.withTransaction {
        writes.markDeleting(scanId)
        if (persistentRow != null) timeline.insert(persistentRow)
    }

    /** "Clear all"'s first step: hide every scan. */
    suspend fun markAllForDelete() = writes.markAllDeleting()

    /**
     * The rest of a delete, idempotent and resumable by the sweep: the scan's own non-persistent
     * Timeline rows (so they stop pinning facts), its telemetry, then the `ScanResult` row.
     */
    suspend fun completeDelete(scanId: Long) {
        db.withTransaction { rows.byScanId(scanId) }
        store.deleteScanTelemetry(scanId)
        scans.deleteById(scanId)
    }

    /** "Clear all" after [markAllForDelete]: every non-persistent row, then each scan's telemetry and row. */
    suspend fun completeDeleteAll() {
        db.withTransaction { rows.allNonPersistent() }
        for (target in writes.sweepTargets()) {
            store.deleteScanTelemetry(target.id)
            scans.deleteById(target.id)
        }
    }

    /** An unaudited cleanup delete (a failed or aborted writer). */
    suspend fun cleanupDelete(scanId: Long) {
        markForDelete(scanId)
        completeDelete(scanId)
    }

    /** Scans the startup sweep must remove. */
    suspend fun sweepTargets(): List<SweepTarget> = writes.sweepTargets()
}
