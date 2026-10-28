package com.androdr.data.repo

import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.SweepTarget
import com.androdr.data.model.EventWatermark
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.SignalMember
import com.androdr.data.model.TelemetryState
import com.androdr.data.store.AtomReader
import com.androdr.data.store.PendingClear
import com.androdr.data.store.TelemetryStore
import com.androdr.sigma.CorrelationSignal
import com.androdr.sigma.Finding
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
    private val findings: FindingsRepository,
    private val pendingClear: PendingClear,
) {
    private val scans get() = db.scanResultDao()
    private val writes get() = db.scanWriteDao()
    private val timeline get() = db.forensicTimelineEventDao()
    private val watermarks get() = db.eventWatermarkDao()
    private val members get() = db.signalMemberDao()
    private val atoms = AtomReader(db)

    /** Opens a session's scan, hidden until [finish]. */
    suspend fun begin(scan: ScanResult) = scans.insertInProgress(scan)

    /** Runs [block] in one Room transaction (a chunk's persist plus its findings, spec §5.2 step 2). */
    suspend fun <T> inTransaction(block: suspend () -> T): T = db.withTransaction { block() }

    /**
     * The session's single finishing transaction (spec §5.2 step 5, Phase D). Every finding is
     * already a `scan_finding` row — evaluate-only ones too, written per chunk (ruling R38) — so:
     *  1. (nothing is buffered);
     *  2. this scan's finding rows, `INSERT … SELECT` from its triggered `scan_finding` rows, and its
     *     detected-change rows;
     *  3. the correlation pass over the atoms read after those inserts (so this scan's rows are `Row`
     *     atoms with their real ids), its signal rows and their `signal_member` rows, and its
     *     correlation findings as STATE `scan_finding` rows (no alert);
     *  4. alerts, set-based, from this scan's alert keys — none left unattached;
     *  5. the guarded `IN_PROGRESS → COMPLETE` update, the event watermarks ([SessionHooks.watermarks])
     *     and the summary columns ([totals] plus the correlation findings).
     * Throws — rolling everything back — with [ScanNotInProgressException] when the guard changes no row.
     */
    suspend fun finish(
        scan: ScanResult, totals: FindingTotals, hooks: SessionHooks, telemetryState: TelemetryState,
    ): Finished = db.withTransaction {
        db.scanFindingDao().insertFindingRows(scan.id, System.currentTimeMillis())
        hooks.extraRows(scan).takeIf { it.isNotEmpty() }?.let { timeline.insertAll(it) }
        val correlation = hooks.correlate(scan, atoms)
        insertSignals(correlation.signals)
        findings.recordState(scan.id, correlation.findings)
        findings.createAlertsForScan(scan.id, scan.timestamp)
        if (scans.complete(scan.id, telemetryState) == 0) throw ScanNotInProgressException(scan.id)
        hooks.watermarks(saveFallback = telemetryState == TelemetryState.FAILED).forEach { (service, position) ->
            watermarks.put(EventWatermark(service, position, scan.id))
        }
        // The summary columns count the correlation findings too; the hooks' counts (known malware,
        // sideloads) stay the session's, as before D2.
        val completed = hooks.summarize((totals + correlation.findings).applyTo(scan), totals)
            .copy(id = scan.id, state = ScanState.COMPLETE, telemetryState = telemetryState)
        writes.update(completed)
        Finished(completed, correlation.findings)
    }

    companion object {
        /** `scan_finding` rows per delete transaction. */
        const val FINDINGS_DELETE_BATCH = 5_000
    }

    /** What [finish] committed: the completed scan and the correlation findings it recorded. */
    class Finished(val scan: ScanResult, val correlationFindings: List<Finding>)

    /** Each signal row, then its members — the only store of member lists (spec §5.4). */
    private suspend fun insertSignals(signals: List<CorrelationSignal>) {
        if (signals.isEmpty()) return
        val ids = timeline.insertAll(signals.map { it.row })
        signals.zip(ids).forEach { (signal, id) ->
            check(id > 0L) { "signal row for ${signal.row.ruleId} was not inserted" }
            members.insertAll(signal.members.map { SignalMember(id, it.kind, it.id) })
        }
    }

    /**
     * First delete step of an unaudited delete, one transaction: hide [scanId] (`DELETING`) and write
     * [persistentRow] if given (the sweep's "import interrupted" row).
     */
    suspend fun markForDelete(scanId: Long, persistentRow: ForensicTimelineEvent? = null) = db.withTransaction {
        writes.markDeleting(scanId)
        if (persistentRow != null) timeline.insert(persistentRow)
    }

    /**
     * A user delete's first step (spec §5.4 step 1), one transaction: build the capped audit summary
     * from the scan's triggered `scan_finding` rows, insert the persistent `scan_deleted` row, and set
     * the scan `DELETING`. False (nothing written) when the scan is not COMPLETE (gone, or already
     * being deleted).
     */
    suspend fun markForAuditedDelete(scanId: Long, now: Long = System.currentTimeMillis()): Boolean =
        db.withTransaction {
            val scan = scans.completeById(scanId) ?: return@withTransaction false
            timeline.insert(DeletionAudit(db.scanFindingDao()).forScan(scan, now))
            writes.markDeleting(scanId)
            true
        }

    /**
     * "Clear all"'s first step (spec §5.4), one transaction: one capped audit row built from every
     * COMPLETE scan's triggered `scan_finding` rows, every scan set `DELETING`, and `clearMaxRowId`
     * (the newest `forensic_timeline` id). Returns the ids it set `DELETING` and `clearMaxRowId`;
     * only these are deleted by [completeDeleteAll], so a scan begun after this (once the caller
     * releases the lock) survives. The caller saves `clearMaxRowId` ([saveClearMark]) before it
     * releases the lock.
     */
    suspend fun markAllForAuditedDelete(now: Long = System.currentTimeMillis()): ClearSnapshot = db.withTransaction {
        val complete = writes.completeCount()
        timeline.insert(DeletionAudit(db.scanFindingDao()).forAll(complete, writes.inProgressCount(), now))
        writes.markAllDeleting()
        ClearSnapshot(writes.sweepTargets().map { it.id }, timeline.maxId())
    }

    /** What "Clear all"'s first transaction set `DELETING`, and the newest row id at that point. */
    data class ClearSnapshot(val scanIds: List<Long>, val clearMaxRowId: Long)

    /** Saves a running "Clear all"'s `clearMaxRowId` (DataStore), so `StartupSweep` can finish it. */
    suspend fun saveClearMark(clearMaxRowId: Long) = pendingClear.save(clearMaxRowId)

    /**
     * The rest of a delete, idempotent and resumable by the sweep (spec §5.4 steps 2–4): the scan's
     * own non-persistent Timeline rows (signal rows with their `signal_member` rows) and its
     * `scan_finding` rows, releasing the facts they alone pinned in the same transactions (its alerts
     * are never deleted and keep pinning theirs), its telemetry, then the `ScanResult` row last.
     */
    suspend fun completeDelete(scanId: Long) {
        db.withTransaction { rows.byScanId(scanId) }
        // A 100k-finding import's rows go in keyset batches, each its own transaction, so deleting an
        // import to free space never needs one huge transaction (review Minor 8). Resumable: a killed
        // delete leaves the scan DELETING and the sweep runs this again.
        val recheckPins = db.scanFindingDao().recheckRecordIdsForScan(scanId)
        do {
            val deleted = db.withTransaction { db.scanFindingDao().deleteBatchForScan(scanId, FINDINGS_DELETE_BATCH) }
        } while (deleted > 0)
        db.withTransaction { store.releaseUnpinned(recheckPins) }
        store.deleteScanTelemetry(scanId)
        scans.deleteById(scanId)
    }

    /**
     * "Clear all" after [markAllForAuditedDelete]: completes the delete of each snapshotted scan, then
     * removes the non-persistent scan-less rows (`scanResultId = -1`, live `dns_query`/`ioc_match` rows
     * among them) with `id <= clearMaxRowId`, and drops the saved mark. No audit row is written here.
     */
    suspend fun completeDeleteAll(snapshot: ClearSnapshot) {
        for (id in snapshot.scanIds) completeDelete(id)
        finishClear(snapshot.clearMaxRowId)
    }

    /** The scan-less rows of a "Clear all" (or a pending one the sweep finishes), then the mark. */
    suspend fun finishClear(clearMaxRowId: Long) {
        db.withTransaction { rows.scanLessThrough(clearMaxRowId) }
        pendingClear.clear()
    }

    /** A pending "Clear all"'s `clearMaxRowId`, if one did not finish. */
    suspend fun pendingClearMark(): Long? = pendingClear.get()

    /** An unaudited cleanup delete (a failed or aborted writer). */
    suspend fun cleanupDelete(scanId: Long) {
        markForDelete(scanId)
        completeDelete(scanId)
    }

    /** Scans the startup sweep must remove. */
    suspend fun sweepTargets(): List<SweepTarget> = writes.sweepTargets()
}
