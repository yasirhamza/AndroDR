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
/** A scan's id and source. */
data class ScanSourceRow(val id: Long, val source: com.androdr.data.model.TelemetrySource)

/** A scan's id and timestamp (the retention walk's keyset position). */
data class ScanKey(val id: Long, val timestamp: Long)

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

    /**
     * Keyset page, newest first: up to [size] `COMPLETE` scans after `(afterTimestamp, afterId)` in
     * `(timestamp, id)` descending order — the id breaks timestamp ties, so two scans stamped the same
     * millisecond across a page boundary both appear (review Minor 9).
     */
    @Query(
        "SELECT * FROM ScanResult WHERE state = 'COMPLETE' AND (timestamp < :afterTimestamp " +
            "OR (timestamp = :afterTimestamp AND id < :afterId)) ORDER BY timestamp DESC, id DESC LIMIT :size"
    )
    suspend fun pagedAfter(afterTimestamp: Long, afterId: Long, size: Int): List<ScanResult>

    /** Keyset page of `COMPLETE` live scans, newest first (the Dashboard diffs the newest two, spec §5.4). */
    @Query(
        "SELECT * FROM ScanResult WHERE state = 'COMPLETE' AND source = 'LIVE_SCAN' " +
            "AND timestamp < :afterTimestamp ORDER BY timestamp DESC, id DESC LIMIT :size"
    )
    suspend fun livePagedAfter(afterTimestamp: Long, size: Int): List<ScanResult>

    /** The prepend query: up to [size] `COMPLETE` scans before `(beforeTimestamp, beforeId)`, nearest first. */
    @Query(
        "SELECT * FROM ScanResult WHERE state = 'COMPLETE' AND (timestamp > :beforeTimestamp " +
            "OR (timestamp = :beforeTimestamp AND id > :beforeId)) ORDER BY timestamp ASC, id ASC LIMIT :size"
    )
    suspend fun pagedBefore(beforeTimestamp: Long, beforeId: Long, size: Int): List<ScanResult>

    /** The `COMPLETE` scan just before [timestamp] (History's diff baseline). */
    @Query(
        "SELECT * FROM ScanResult WHERE state = 'COMPLETE' AND timestamp = (SELECT MAX(timestamp) " +
            "FROM ScanResult WHERE state = 'COMPLETE' AND timestamp < :timestamp) ORDER BY id DESC"
    )
    suspend fun previousOf(timestamp: Long): List<ScanResult>

    /** True when at least one scan is listed (History's empty state). */
    @Query("SELECT EXISTS (SELECT 1 FROM ScanResult WHERE state = 'COMPLETE')")
    fun anyComplete(): Flow<Boolean>

    /** The sources of the scans among [ids] that still exist (a report names who opened an alert). */
    @Query("SELECT id, source FROM ScanResult WHERE id IN (:ids)")
    suspend fun sourcesOf(ids: List<Long>): List<ScanSourceRow>

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

    /**
     * Retention's walk (spec §5.1): up to [size] `COMPLETE` live scans after `(afterTimestamp, afterId)`,
     * newest first, ids only. `ScanResult` holds one row per scan.
     */
    @Query(
        "SELECT id, timestamp FROM ScanResult WHERE state = 'COMPLETE' AND source = 'LIVE_SCAN' " +
            "AND (timestamp < :afterTimestamp OR (timestamp = :afterTimestamp AND id < :afterId)) " +
            "ORDER BY timestamp DESC, id DESC LIMIT :size"
    )
    suspend fun liveKeysAfter(afterTimestamp: Long, afterId: Long, size: Int): List<ScanKey>

    /** True while [id] is `COMPLETE` (a retention batch never touches a scan being deleted). */
    @Query("SELECT EXISTS (SELECT 1 FROM ScanResult WHERE id = :id AND state = 'COMPLETE')")
    suspend fun isComplete(id: Long): Boolean

    /** How many `COMPLETE` live scans are newer than `(timestamp, id)` now (retention re-checks a rank). */
    @Query(
        "SELECT COUNT(*) FROM ScanResult WHERE state = 'COMPLETE' AND source = 'LIVE_SCAN' " +
            "AND (timestamp > :timestamp OR (timestamp = :timestamp AND id > :id))"
    )
    suspend fun liveNewerThan(timestamp: Long, id: Long): Int

    /**
     * Sets [id]'s `telemetryState` to [state] only while it is [from] (retention marks a `STORED` scan
     * `PARTIAL_RETENTION` and a `FAILED` one `FAILED_PARTIAL_RETENTION`). Returns the number of rows changed.
     */
    @Query("UPDATE ScanResult SET telemetryState = :state WHERE id = :id AND telemetryState = :from")
    suspend fun setTelemetryState(id: Long, state: TelemetryState, from: TelemetryState): Int

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
