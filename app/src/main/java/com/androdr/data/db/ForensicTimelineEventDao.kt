package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import kotlinx.coroutines.flow.Flow

@Dao
@Suppress("TooManyFunctions") // Room DAO with filtered queries for timeline
interface ForensicTimelineEventDao {

    @Query("SELECT * FROM forensic_timeline ORDER BY startTimestamp DESC LIMIT :limit")
    fun getRecentEvents(limit: Int = 500): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline
        WHERE source = :source
        ORDER BY startTimestamp DESC LIMIT :limit
    """)
    fun getEventsBySource(source: String, limit: Int = 500): Flow<List<ForensicTimelineEvent>>

    /**
     * Rows of one source belonging to ONE scan (#342 C4). A report embeds
     * imported intrusion-log evidence only when it is the report FOR that import,
     * identified by the scan's id — a live-scan report (or a historical one from
     * before any import) matches no intrusion-log rows and embeds none.
     */
    @Query("""
        SELECT * FROM forensic_timeline
        WHERE source = :source AND scanResultId = :scanResultId
        ORDER BY startTimestamp DESC LIMIT :limit
    """)
    fun getEventsBySourceForScan(
        source: String,
        scanResultId: Long,
        limit: Int = 500,
    ): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline
        WHERE packageName = :packageName
        ORDER BY startTimestamp DESC LIMIT 500
    """)
    fun getEventsByPackage(packageName: String): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline
        WHERE startTimestamp BETWEEN :startMs AND :endMs
        ORDER BY startTimestamp DESC LIMIT 500
    """)
    fun getEventsInRange(startMs: Long, endMs: Long): Flow<List<ForensicTimelineEvent>>

    @Query("SELECT DISTINCT source FROM forensic_timeline ORDER BY source")
    suspend fun getDistinctSources(): List<String>

    @Query("SELECT DISTINCT packageName FROM forensic_timeline WHERE packageName != '' ORDER BY packageName")
    suspend fun getDistinctPackages(): List<String>

    @Query("SELECT DISTINCT packageName FROM forensic_timeline WHERE category = 'package_install'")
    suspend fun getInstalledPackagesAlreadyEmitted(): List<String>

    @Query("SELECT DISTINCT packageName FROM forensic_timeline WHERE category = 'device_admin_grant'")
    suspend fun getAdminGrantedPackagesAlreadyEmitted(): List<String>

    @Query("SELECT * FROM forensic_timeline ORDER BY startTimestamp ASC LIMIT 10000")
    suspend fun getAllForExport(): List<ForensicTimelineEvent>

    @Query("SELECT * FROM forensic_timeline WHERE startTimestamp >= :sinceMs ORDER BY startTimestamp ASC")
    suspend fun getEventsSince(sinceMs: Long): List<ForensicTimelineEvent>

    /**
     * Like [getEventsSince] but drops rows whose [ForensicTimelineEvent.telemetrySource]
     * equals [excluded] (#342 B2).
     *
     * The live-scan correlation lookback uses this with
     * `excluded = INTRUSION_LOG_IMPORT`: imported forensic snapshots carry each
     * event's OWN (historical) timestamp, so a plain time-window query pulls them
     * into a live scan's correlation input. Any signal they help produce is then
     * stamped with the LIVE scan's id, which the intrusion-log replace-on-reimport
     * sweep (keyed on intrusion_log scan ids) can never reach — an orphan signal
     * accumulating per live scan. Excluding imported rows keeps a live scan's
     * correlation to live/bug-report evidence. [getEventsSince] is retained
     * unchanged for any caller that genuinely wants every source.
     */
    @Query("""
        SELECT * FROM forensic_timeline
        WHERE startTimestamp >= :sinceMs AND telemetrySource != :excluded
        ORDER BY startTimestamp ASC
    """)
    suspend fun getEventsSinceExcludingTelemetrySource(
        sinceMs: Long,
        excluded: TelemetrySource
    ): List<ForensicTimelineEvent>

    /**
     * Bulk insert returning the Room-assigned autoincrement IDs, in the same
     * order as the input list. The correlation engine needs these IDs so that
     * `matchContext.member_event_ids` can reference real rows (otherwise every
     * member would be serialized as `id = 0` from the default value).
     *
     * Rows that were skipped by `OnConflictStrategy.IGNORE` get a `-1` entry.
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(events: List<ForensicTimelineEvent>): List<Long>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(event: ForensicTimelineEvent): Long

    @Query("DELETE FROM forensic_timeline WHERE createdAt < :cutoff")
    suspend fun deleteOlderThan(cutoff: Long)

    @Query("DELETE FROM forensic_timeline WHERE source = :source")
    suspend fun deleteBySource(source: String)

    @Query("DELETE FROM forensic_timeline WHERE scanResultId = :scanResultId")
    suspend fun deleteByScanId(scanResultId: Long)

    /**
     * Scan ids that own at least one row with the given [source] (#342).
     *
     * Used by the intrusion-log import's replace-on-reimport sweep: deleting by
     * source alone would strand the correlation-signal rows the engine writes
     * with `source = "sigma_correlation_engine"`, leaving clusters whose
     * `member_event_ids` point at deleted rows. Deleting by the ids this
     * returns removes a prior import's raw rows, finding rows, and signals
     * together — without touching live-scan or bug-report signals, which carry
     * their own scan ids.
     *
     * `scanResultId != -1` filters the "not associated with any scan" sentinel
     * ([ForensicTimelineEvent.scanResultId] default), which must never be swept.
     */
    @Query("SELECT DISTINCT scanResultId FROM forensic_timeline WHERE source = :source AND scanResultId != -1")
    suspend fun getDistinctScanIdsBySource(source: String): List<Long>

    @Query("DELETE FROM forensic_timeline")
    suspend fun deleteAll()
}
