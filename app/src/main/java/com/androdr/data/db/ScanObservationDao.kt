package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.ScanObservation

/** A position on the observation PK `(scanId, service, ordinal)` and the fact it observes. */
data class ObservationKey(val service: String, val ordinal: Int, val recordId: Long)

data class OrdinalFact(val ordinal: Int, val recordId: Long)

/** An observation's rowid and the fact it observes (a retention batch deletes by rowid). */
data class ObservationRow(val rowId: Long, val recordId: Long)

/** Observations (`scan_record`): writer/deleter side. List-parameter queries go through [chunkedIn]. */
@Dao
interface ScanObservationDao {

    /** Returns each row's rowid, or -1 for a duplicate `(scanId, recordId)` or PK. */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIgnore(observations: List<ScanObservation>): List<Long>

    /** Keyset on the PK: the next [size] observations of [scanId] after `(afterService, afterOrdinal)`. */
    @Query(
        "SELECT service, ordinal, recordId FROM scan_record WHERE scanId = :scanId AND service >= :afterService " +
            "AND (service > :afterService OR ordinal > :afterOrdinal) ORDER BY service, ordinal LIMIT :size"
    )
    suspend fun factIdsAfter(scanId: Long, afterService: String, afterOrdinal: Int, size: Int): List<ObservationKey>

    @Query("DELETE FROM scan_record WHERE scanId = :scanId")
    suspend fun deleteForScan(scanId: Long)

    /** Deletes [scanId]'s observations up to and including `(service, ordinal)` in PK order. */
    @Query(
        "DELETE FROM scan_record WHERE scanId = :scanId " +
            "AND (service < :service OR (service = :service AND ordinal <= :ordinal))"
    )
    suspend fun deleteThrough(scanId: Long, service: String, ordinal: Int)

    @Query(
        "SELECT ordinal, recordId FROM scan_record WHERE scanId = :scanId AND service = :service " +
            "AND ordinal IN (:ordinals)"
    )
    suspend fun factIdsForOrdinals(scanId: Long, service: String, ordinals: List<Int>): List<OrdinalFact>

    /**
     * Retention (spec §5.1): up to [size] of [scanId]'s event observations stamped before [cutoff]
     * (index `(scanId, eventTime)`; a NULL event time — a snapshot — is never `<`). Each batch
     * deletes what it read, so the next call continues where it stopped.
     */
    @Query("$RETENTION_EVENT_BATCH")
    suspend fun retentionEventBatch(scanId: Long, cutoff: Long, size: Int): List<ObservationRow>

    /** Retention: up to [size] of [scanId]'s snapshot observations (`eventTime IS NULL`). */
    @Query("$RETENTION_SNAPSHOT_BATCH")
    suspend fun retentionSnapshotBatch(scanId: Long, size: Int): List<ObservationRow>

    /** Deletes the observations [rowIds]. Call through [chunkedEach]. */
    @Query("$DELETE_OBSERVATION_ROWS")
    suspend fun deleteRows(rowIds: List<Long>)
}

internal const val RETENTION_EVENT_BATCH = "SELECT rowid AS rowId, recordId FROM scan_record " +
    "WHERE scanId = :scanId AND eventTime < :cutoff LIMIT :size"

internal const val RETENTION_SNAPSHOT_BATCH = "SELECT rowid AS rowId, recordId FROM scan_record " +
    "WHERE scanId = :scanId AND eventTime IS NULL LIMIT :size"

internal const val DELETE_OBSERVATION_ROWS = "DELETE FROM scan_record WHERE rowid IN (:rowIds)"
