package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.Indicator

@Dao
@Suppress("TooManyFunctions") // Each query method is a distinct, narrowly-scoped DAO access;
// splitting into multiple DAOs would fragment the single `indicators` table with no benefit.
interface IndicatorDao {

    @Query("SELECT * FROM indicators WHERE type = :type AND value = :value LIMIT 1")
    suspend fun lookup(type: String, value: String): Indicator?

    @Query("SELECT * FROM indicators WHERE type = :type")
    suspend fun getAllByType(type: String): List<Indicator>

    /**
     * Lightweight projection returning only the `value` column. Used by
     * `DomainBloomIndex` to build the in-memory domain lookup index without
     * materializing ~371k full Indicator rows (and their string columns) on
     * every refresh.
     */
    @Query("SELECT value FROM indicators WHERE type = :type")
    suspend fun getValuesByType(type: String): List<String>

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

    @Query("SELECT MAX(fetchedAt) FROM indicators")
    suspend fun lastFetchTimeGlobal(): Long?

    @Query("SELECT DISTINCT source FROM indicators ORDER BY source")
    suspend fun allSources(): List<String>
}
