package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.androdr.data.model.DnsEvent
import kotlinx.coroutines.flow.Flow

@Dao
interface DnsEventDao {

    @Query("SELECT * FROM DnsEvent ORDER BY timestamp DESC LIMIT 200")
    fun getRecentEvents(): Flow<List<DnsEvent>>

    @Query("SELECT * FROM DnsEvent WHERE reason IS NOT NULL ORDER BY timestamp DESC")
    fun getMatchedEvents(): Flow<List<DnsEvent>>

    /** One-shot snapshot for report export; not a Flow. */
    @Query("SELECT * FROM DnsEvent ORDER BY timestamp DESC LIMIT 500")
    suspend fun getRecentSnapshot(): List<DnsEvent>

    @Insert
    suspend fun insert(event: DnsEvent)

    /** Batched insert used by the VPN packet path to amortize Room transaction overhead. */
    @Insert
    suspend fun insertAll(events: List<DnsEvent>)

    @Query("DELETE FROM DnsEvent WHERE timestamp < :cutoff")
    suspend fun deleteOlderThan(cutoff: Long)
}
