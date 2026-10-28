package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Update
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource

/** A scan the startup sweep must finish removing, with what it needs to decide on an "interrupted" row. */
data class SweepTarget(val id: Long, val state: ScanState, val source: TelemetrySource, val timestamp: Long)

/**
 * The writer session's and the deleters' `ScanResult` statements (spec §5.1–5.2), kept apart from
 * [ScanResultDao]'s list reads. The guarded finish itself is [ScanResultDao.complete].
 */
@Dao
interface ScanWriteDao {

    /** Rewrites a scan row the caller has just completed through [ScanResultDao.complete]. */
    @Update
    suspend fun update(scan: ScanResult)

    /** Hides [id] for deletion (spec §5.1 Delete); idempotent. */
    @Query("UPDATE ScanResult SET state = 'DELETING' WHERE id = :id")
    suspend fun markDeleting(id: Long)

    /** "Clear all": hides every scan for deletion. */
    @Query("UPDATE ScanResult SET state = 'DELETING'")
    suspend fun markAllDeleting()

    /** How many scans are COMPLETE ("Clear all"'s audit row). */
    @Query("SELECT COUNT(*) FROM ScanResult WHERE state = 'COMPLETE'")
    suspend fun completeCount(): Int

    @Query("SELECT state FROM ScanResult WHERE id = :id")
    suspend fun stateOf(id: Long): ScanState?

    /** Every scan the sweep (or "Clear all") must remove: IN_PROGRESS and DELETING. */
    @Query("SELECT id, state, source, timestamp FROM ScanResult WHERE state IN ('IN_PROGRESS', 'DELETING')")
    suspend fun sweepTargets(): List<SweepTarget>
}
