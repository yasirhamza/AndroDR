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

    /**
     * Keyset over row ids: up to [size] rows with `afterId < id <= untilId`, ascending. The live
     * scan collects DNS by id (spec §5.2 Watermarks), so a late-flushed row is never skipped.
     */
    @Query("SELECT * FROM DnsEvent WHERE id > :afterId AND id <= :untilId ORDER BY id LIMIT :size")
    suspend fun eventsAfterId(afterId: Long, untilId: Long, size: Int): List<DnsEvent>

    /** The newest row id, or null when no row is stored. */
    @Query("SELECT MAX(id) FROM DnsEvent")
    suspend fun maxId(): Long?

    /** The lowest id among rows stamped at or after [ts] (where a first collection starts). */
    @Query("SELECT MIN(id) FROM DnsEvent WHERE timestamp >= :ts")
    suspend fun minIdSince(ts: Long): Long?

    /** Returns the row id: the live DNS fact's source event key is `"dns:$id"`. */
    @Insert
    suspend fun insert(event: DnsEvent): Long

    /** Batched insert used by the VPN packet path to amortize Room transaction overhead; ids in order. */
    @Insert
    suspend fun insertAll(events: List<DnsEvent>): List<Long>

    @Query("DELETE FROM DnsEvent WHERE timestamp < :cutoff")
    suspend fun deleteOlderThan(cutoff: Long)
}
