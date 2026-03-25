package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.DomainIocEntry

@Dao
interface DomainIocEntryDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<DomainIocEntry>)

    @Query("SELECT * FROM domain_ioc_entries")
    suspend fun getAll(): List<DomainIocEntry>

    @Query("SELECT COUNT(*) FROM domain_ioc_entries")
    suspend fun count(): Int

    @Query("DELETE FROM domain_ioc_entries WHERE source = :source AND fetchedAt < :olderThan")
    suspend fun deleteStaleEntries(source: String, olderThan: Long)

    @Query("SELECT MAX(fetchedAt) FROM domain_ioc_entries")
    suspend fun mostRecentFetchTime(): Long?
}
