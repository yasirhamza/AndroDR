package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.RecordBody

/** Content bodies (`record_body`). List-parameter queries must be called through [chunkedEach]. */
@Dao
interface RecordBodyDao {

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIgnore(bodies: List<RecordBody>)

    /** Deletes those of [hashes] that no fact references any more. */
    @Query(
        "DELETE FROM record_body WHERE hash IN (:hashes) " +
            "AND NOT EXISTS (SELECT 1 FROM telemetry_record t WHERE t.bodyHash = record_body.hash)"
    )
    suspend fun deleteUnreferenced(hashes: List<ByteArray>)
}
