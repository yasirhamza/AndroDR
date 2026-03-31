package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.Indicator

@Dao
interface IndicatorDao {

    @Query("SELECT * FROM indicators WHERE type = :type AND value = :value LIMIT 1")
    suspend fun lookup(type: String, value: String): Indicator?

    @Query("SELECT * FROM indicators WHERE type = :type")
    suspend fun getAllByType(type: String): List<Indicator>

    @Query("SELECT * FROM indicators")
    suspend fun getAll(): List<Indicator>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<Indicator>)

    @Query("SELECT COUNT(*) FROM indicators")
    suspend fun count(): Int

    @Query("SELECT COUNT(*) FROM indicators WHERE type = :type")
    suspend fun countByType(type: String): Int

    @Query("DELETE FROM indicators WHERE source = :source AND fetchedAt < :olderThan")
    suspend fun deleteStaleEntries(source: String, olderThan: Long)

    @Query("SELECT MAX(fetchedAt) FROM indicators WHERE source = :source")
    suspend fun lastFetchTime(source: String): Long?
}
