package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.androdr.data.model.DnsEvent
import kotlinx.coroutines.flow.Flow

@Suppress("TooManyFunctions") // one method per DNS-log access: monitor, live scan, retention and privacy scan
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

    // Privacy scan reads. The DNS log has no row cap (only age-based deletion) and a hostile app can flood it, so
    // every read here is bounded, and nothing is ranked by lookup count before matching: junk domains can cost
    // time (deadline -> TRUNCATED) but can never push a real tracker pair out of a top-N window.

    /**
     * One page of [app]'s distinct raw domains after [afterDomain] (start with ""), in ascending order. Paged per
     * installed app, so one app (whatever its name sorts as) can only spend its own quota;
     * `appName = :app AND domain > :afterDomain` seeks `index_DnsEvent_appName_domain_timestamp` directly.
     */
    @Query(
        "SELECT DISTINCT domain FROM DnsEvent WHERE appName = :app AND domain > :afterDomain AND timestamp >= :since " +
            "ORDER BY domain LIMIT :limit"
    )
    suspend fun domainsAfter(since: Long, app: String, afterDomain: String, limit: Int): List<String>

    /** Called only for pairs that matched the tracker registry; [domain] is the raw stored value. */
    @Query(
        "SELECT COUNT(*) AS lookups, GROUP_CONCAT(DISTINCT timestamp / 86400000) AS dayList, " +
            "MIN(timestamp) AS firstAt, MAX(timestamp) AS lastAt " +
            "FROM DnsEvent WHERE appName = :app AND domain = :domain AND timestamp >= :since"
    )
    suspend fun lookupCount(since: Long, app: String, domain: String): DomainLookupCount

    /** Served by `index_DnsEvent_appName_domain_timestamp`; [domain] is the raw stored value, never normalised. */
    @Query(
        "SELECT timestamp FROM DnsEvent WHERE appName = :app AND domain = :domain AND timestamp >= :since " +
            "ORDER BY timestamp LIMIT :limit"
    )
    suspend fun lookupTimes(since: Long, app: String, domain: String, limit: Int): List<Long>

    /** UTC days since [since] with at least one attributed lookup; 0 = the monitor recorded nothing attributable. */
    @Query(
        "SELECT COUNT(DISTINCT timestamp / 86400000) FROM DnsEvent WHERE timestamp >= :since AND appName IS NOT NULL"
    )
    suspend fun coverageDaysSince(since: Long): Int
}

/** One (app, raw domain) pair's lookups since a window start. [dayList] is comma-joined UTC day numbers. */
data class DomainLookupCount(
    val lookups: Int,
    val dayList: String?,
    val firstAt: Long?,
    val lastAt: Long?,
)
