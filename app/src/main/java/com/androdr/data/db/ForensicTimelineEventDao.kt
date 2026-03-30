package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.ForensicTimelineEvent
import kotlinx.coroutines.flow.Flow

@Dao
interface ForensicTimelineEventDao {

    @Query("SELECT * FROM forensic_timeline ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentEvents(limit: Int = 500): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline
        WHERE severity IN (:severities)
        ORDER BY timestamp DESC LIMIT :limit
    """)
    fun getEventsBySeverity(severities: List<String>, limit: Int = 500): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline
        WHERE source = :source
        ORDER BY timestamp DESC LIMIT :limit
    """)
    fun getEventsBySource(source: String, limit: Int = 500): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline
        WHERE packageName = :packageName
        ORDER BY timestamp DESC LIMIT 500
    """)
    fun getEventsByPackage(packageName: String): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline
        WHERE timestamp BETWEEN :startMs AND :endMs
        ORDER BY timestamp DESC LIMIT 500
    """)
    fun getEventsInRange(startMs: Long, endMs: Long): Flow<List<ForensicTimelineEvent>>

    @Query("SELECT DISTINCT source FROM forensic_timeline ORDER BY source")
    suspend fun getDistinctSources(): List<String>

    @Query("SELECT DISTINCT packageName FROM forensic_timeline WHERE packageName != '' ORDER BY packageName")
    suspend fun getDistinctPackages(): List<String>

    @Query("SELECT * FROM forensic_timeline ORDER BY timestamp ASC LIMIT 10000")
    suspend fun getAllForExport(): List<ForensicTimelineEvent>

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertAll(events: List<ForensicTimelineEvent>)

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(event: ForensicTimelineEvent)

    @Query("DELETE FROM forensic_timeline WHERE createdAt < :cutoff")
    suspend fun deleteOlderThan(cutoff: Long)

    @Query("DELETE FROM forensic_timeline WHERE source = :source")
    suspend fun deleteBySource(source: String)
}
