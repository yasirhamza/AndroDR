package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.FeedHealth

@Dao
interface FeedHealthDao {

    @Query("SELECT * FROM feed_health WHERE feedId = :feedId")
    suspend fun get(feedId: String): FeedHealth?

    @Query("SELECT * FROM feed_health")
    suspend fun getAll(): List<FeedHealth>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(health: FeedHealth)

    /**
     * Feeds whose last SUCCESSFUL refresh is older than [threshold] (ms epoch),
     * including feeds that have never succeeded (lastSuccessAt = 0). This is the
     * "which feeds are stale" query — never a global MAX, so a single healthy
     * feed cannot mask the rest.
     */
    @Query("SELECT * FROM feed_health WHERE lastSuccessAt < :threshold")
    suspend fun staleSince(threshold: Long): List<FeedHealth>
}
