package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetryState
import kotlinx.coroutines.flow.Flow

/** Every list query shows only `COMPLETE` scans (spec §5.1 Visibility). */
@Dao
interface ScanResultDao {

    @Query("SELECT * FROM ScanResult WHERE state = 'COMPLETE' ORDER BY timestamp DESC LIMIT 50")
    fun getAllScans(): Flow<List<ScanResult>>

    @Query("SELECT * FROM ScanResult WHERE state = 'COMPLETE' ORDER BY timestamp DESC LIMIT 2")
    suspend fun getLatestTwo(): List<ScanResult>

    @Insert
    suspend fun insert(scan: ScanResult)

    /** Opens a writer session's scan: inserted hidden ([ScanState.IN_PROGRESS]) until [complete]. */
    suspend fun insertInProgress(scan: ScanResult) = insert(scan.copy(state = ScanState.IN_PROGRESS))

    /**
     * Guarded finish: marks [id] COMPLETE only if it is still IN_PROGRESS. Returns the number of
     * rows changed; 0 means the scan was deleted or marked DELETING meanwhile.
     */
    @Query(
        "UPDATE ScanResult SET state = 'COMPLETE', telemetryState = :telemetryState " +
            "WHERE id = :id AND state = 'IN_PROGRESS'"
    )
    suspend fun complete(id: Long, telemetryState: TelemetryState): Int

    /** Scans the startup sweep must finish removing: IN_PROGRESS (killed writer) and DELETING. */
    @Query("SELECT id FROM ScanResult WHERE state IN ('IN_PROGRESS', 'DELETING')")
    suspend fun sweepableIds(): List<Long>

    @Query("DELETE FROM ScanResult WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM ScanResult")
    suspend fun deleteAll()
}
