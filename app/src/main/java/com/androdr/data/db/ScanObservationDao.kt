package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.ScanObservation

/** A position on the observation PK `(scanId, service, ordinal)` and the fact it observes. */
data class ObservationKey(val service: String, val ordinal: Int, val recordId: Long)

data class OrdinalFact(val ordinal: Int, val recordId: Long)

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

    @Query(
        "SELECT ordinal, recordId FROM scan_record WHERE scanId = :scanId AND service = :service " +
            "AND ordinal IN (:ordinals)"
    )
    suspend fun factIdsForOrdinals(scanId: Long, service: String, ordinals: List<Int>): List<OrdinalFact>
}
