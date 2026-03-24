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

    @Query("SELECT * FROM DnsEvent WHERE isBlocked = 1 ORDER BY timestamp DESC")
    fun getBlockedEvents(): Flow<List<DnsEvent>>

    @Insert
    suspend fun insert(event: DnsEvent)

    @Query("DELETE FROM DnsEvent WHERE timestamp < :cutoff")
    suspend fun deleteOlderThan(cutoff: Long)
}
