package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetryState
import kotlinx.coroutines.flow.Flow

/**
 * Every list query shows only `COMPLETE` scans (spec §5.1 Visibility). There is no capped "all
 * scans" list (spec §5.5): lists page by keyset on `timestamp` ([pagedAfter] / [pagedBefore]).
 */
@Dao
@Suppress("TooManyFunctions") // Room DAO: list pages, latest-scan reads, the writer's guarded statements
interface ScanResultDao {

    @Query("SELECT * FROM ScanResult WHERE state = 'COMPLETE' ORDER BY timestamp DESC LIMIT 2")
    suspend fun getLatestTwo(): List<ScanResult>

    /** The newest `COMPLETE` live scan (state findings follow it, spec §5.4), re-emitted on change. */
    @Query("SELECT * FROM ScanResult WHERE id = ($LATEST_LIVE_ID)")
    fun latestLive(): Flow<ScanResult?>

    /** [latestLive], read once. */
    @Query("SELECT * FROM ScanResult WHERE id = ($LATEST_LIVE_ID)")
    suspend fun latestLiveOnce(): ScanResult?

    /** Keyset page, newest first: up to [size] `COMPLETE` scans older than [afterTimestamp]. */
    @Query(
        "SELECT * FROM ScanResult WHERE state = 'COMPLETE' AND timestamp < :afterTimestamp " +
            "ORDER BY timestamp DESC LIMIT :size"
    )
    suspend fun pagedAfter(afterTimestamp: Long, size: Int): List<ScanResult>

    /** The prepend query: up to [size] `COMPLETE` scans newer than [beforeTimestamp], oldest first. */
    @Query(
        "SELECT * FROM ScanResult WHERE state = 'COMPLETE' AND timestamp > :beforeTimestamp " +
            "ORDER BY timestamp ASC LIMIT :size"
    )
    suspend fun pagedBefore(beforeTimestamp: Long, size: Int): List<ScanResult>

    /** The `COMPLETE` scan just before [timestamp] (History's diff baseline). */
    @Query(
        "SELECT * FROM ScanResult WHERE state = 'COMPLETE' AND timestamp = (SELECT MAX(timestamp) " +
            "FROM ScanResult WHERE state = 'COMPLETE' AND timestamp < :timestamp) ORDER BY id DESC"
    )
    suspend fun previousOf(timestamp: Long): List<ScanResult>

    /** True when at least one scan is listed (History's empty state). */
    @Query("SELECT EXISTS (SELECT 1 FROM ScanResult WHERE state = 'COMPLETE')")
    fun anyComplete(): Flow<Boolean>

    @Query("SELECT * FROM ScanResult WHERE id = :id AND state = 'COMPLETE'")
    suspend fun completeById(id: Long): ScanResult?

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

/** The id of the newest `COMPLETE` live scan (newest timestamp, then highest id). */
internal const val LATEST_LIVE_ID = "SELECT l.id FROM ScanResult l WHERE l.state = 'COMPLETE' AND " +
    "l.source = 'LIVE_SCAN' AND l.timestamp = (SELECT MAX(m.timestamp) FROM ScanResult m " +
    "WHERE m.state = 'COMPLETE' AND m.source = 'LIVE_SCAN') ORDER BY l.id DESC"
