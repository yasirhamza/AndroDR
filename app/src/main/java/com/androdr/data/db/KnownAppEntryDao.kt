package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface KnownAppEntryDao {

    @Query("SELECT * FROM known_app_entries")
    suspend fun getAll(): List<KnownAppDbEntry>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<KnownAppDbEntry>)

    @Query("DELETE FROM known_app_entries WHERE sourceId = :sourceId AND fetchedAt < :olderThan")
    suspend fun deleteStaleEntries(sourceId: String, olderThan: Long)

    @Query("SELECT COUNT(*) FROM known_app_entries")
    suspend fun count(): Int

    @Query("SELECT MAX(fetchedAt) FROM known_app_entries")
    suspend fun mostRecentFetchTime(): Long?
}
