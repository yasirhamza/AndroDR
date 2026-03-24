package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.IocEntry

@Dao
interface IocEntryDao {

    @Query("SELECT * FROM ioc_entries WHERE packageName = :packageName LIMIT 1")
    suspend fun getByPackageName(packageName: String): IocEntry?

    @Query("SELECT * FROM ioc_entries")
    suspend fun getAll(): List<IocEntry>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<IocEntry>)

    @Query("SELECT COUNT(*) FROM ioc_entries")
    suspend fun count(): Int

    @Query("SELECT MAX(fetchedAt) FROM ioc_entries WHERE source = :source")
    suspend fun lastFetchTime(source: String): Long?

    /** Removes entries from [source] that were not refreshed in the latest fetch run. */
    @Query("DELETE FROM ioc_entries WHERE source = :source AND fetchedAt < :olderThan")
    suspend fun deleteStaleEntries(source: String, olderThan: Long)
}
