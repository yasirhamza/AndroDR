package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.ForensicTimelineEvent
import kotlinx.coroutines.flow.Flow

/** A finding row's rule and fact (see [ForensicTimelineEventDao.findingRuleRecords]). */
data class RuleRecord(val ruleId: String, val recordId: Long)

@Dao
@Suppress("TooManyFunctions") // Room DAO with filtered queries for timeline
interface ForensicTimelineEventDao {

    // Reads below show only visible rows (spec §5.1 Visibility: `VisibleRow`), so rows of an
    // IN_PROGRESS or DELETING scan never reach the Timeline, a report or an export.

    @Query("SELECT * FROM forensic_timeline r WHERE ${VisibleRow.SQL} ORDER BY r.startTimestamp DESC LIMIT :limit")
    fun getRecentEvents(limit: Int = 500): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline r
        WHERE r.source = :source AND ${VisibleRow.SQL}
        ORDER BY r.startTimestamp DESC LIMIT :limit
    """)
    fun getEventsBySource(source: String, limit: Int = 500): Flow<List<ForensicTimelineEvent>>

    /**
     * Rows of one source belonging to ONE scan (#342 C4). A report embeds
     * imported intrusion-log evidence only when it is the report FOR that import,
     * identified by the scan's id — a live-scan report (or a historical one from
     * before any import) matches no intrusion-log rows and embeds none.
     */
    @Query("""
        SELECT * FROM forensic_timeline r
        WHERE r.source = :source AND r.scanResultId = :scanResultId AND ${VisibleRow.SQL}
        ORDER BY r.startTimestamp DESC LIMIT :limit
    """)
    fun getEventsBySourceForScan(
        source: String,
        scanResultId: Long,
        limit: Int = 500,
    ): Flow<List<ForensicTimelineEvent>>

    /**
     * One scan's visible rows (the import screen's link, C3): its finding rows, signals and detected
     * changes. No row cap (spec §5.5); C4 replaces this read with the keyset-paged union.
     */
    @Query("""
        SELECT * FROM forensic_timeline r
        WHERE r.scanResultId = :scanResultId AND ${VisibleRow.SQL}
        ORDER BY r.startTimestamp DESC
    """)
    fun getEventsByScan(scanResultId: Long): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline r
        WHERE r.packageName = :packageName AND ${VisibleRow.SQL}
        ORDER BY r.startTimestamp DESC LIMIT 500
    """)
    fun getEventsByPackage(packageName: String): Flow<List<ForensicTimelineEvent>>

    @Query("""
        SELECT * FROM forensic_timeline r
        WHERE r.startTimestamp BETWEEN :startMs AND :endMs AND ${VisibleRow.SQL}
        ORDER BY r.startTimestamp DESC LIMIT 500
    """)
    fun getEventsInRange(startMs: Long, endMs: Long): Flow<List<ForensicTimelineEvent>>

    @Query("SELECT DISTINCT r.source FROM forensic_timeline r WHERE ${VisibleRow.SQL} ORDER BY r.source")
    suspend fun getDistinctSources(): List<String>

    @Query(
        "SELECT DISTINCT r.packageName FROM forensic_timeline r WHERE r.packageName != '' AND ${VisibleRow.SQL} " +
            "ORDER BY r.packageName"
    )
    suspend fun getDistinctPackages(): List<String>

    @Query("SELECT DISTINCT packageName FROM forensic_timeline WHERE category = 'package_install'")
    suspend fun getInstalledPackagesAlreadyEmitted(): List<String>

    @Query("SELECT DISTINCT packageName FROM forensic_timeline WHERE category = 'device_admin_grant'")
    suspend fun getAdminGrantedPackagesAlreadyEmitted(): List<String>

    @Query("SELECT * FROM forensic_timeline r WHERE ${VisibleRow.SQL} ORDER BY r.startTimestamp ASC LIMIT 10000")
    suspend fun getAllForExport(): List<ForensicTimelineEvent>

    @Query(
        "SELECT * FROM forensic_timeline r WHERE r.startTimestamp >= :sinceMs AND ${VisibleRow.SQL} " +
            "ORDER BY r.startTimestamp ASC"
    )
    suspend fun getEventsSince(sinceMs: Long): List<ForensicTimelineEvent>

    /** The visible rows among [ids] (correlation-cluster members, spec §5.4). Call through [chunkedIn]. */
    @Query("SELECT * FROM forensic_timeline r WHERE r.id IN (:ids) AND ${VisibleRow.SQL}")
    suspend fun visibleByIds(ids: List<Long>): List<ForensicTimelineEvent>

    /**
     * Bulk insert returning the Room-assigned autoincrement IDs, in the same
     * order as the input list. A signal's `signal_member` rows need its real id.
     *
     * Rows that were skipped by `OnConflictStrategy.IGNORE` get a `-1` entry.
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(events: List<ForensicTimelineEvent>): List<Long>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(event: ForensicTimelineEvent): Long

    // Every delete below removes rows that may pin facts (`recordId`). Call them only through
    // `TimelineRowDeleter`, which reads the paired `recordIds*` first and releases those facts in
    // the same transaction (spec §5.1 Pins; gated by TimelineRowDeleterTest).

    /** The 30-day prune; persistent (audit/closure) rows are never pruned. */
    @Query("DELETE FROM forensic_timeline WHERE createdAt < :cutoff AND persistent = 0")
    suspend fun deleteOlderThan(cutoff: Long)

    // The signal rows each delete below is about to remove: their `signal_member` rows go with
    // them, by id (TimelineRowDeleter; spec §5.4). Same predicates as the paired deletes.

    @Query("SELECT id FROM forensic_timeline WHERE kind = 'signal' AND createdAt < :cutoff AND persistent = 0")
    suspend fun signalIdsOlderThan(cutoff: Long): List<Long>

    @Query("SELECT id FROM forensic_timeline WHERE kind = 'signal' AND id IN (:ids)")
    suspend fun signalIdsByIds(ids: List<Long>): List<Long>

    @Query("SELECT id FROM forensic_timeline WHERE kind = 'signal' AND scanResultId = :scanResultId AND persistent = 0")
    suspend fun signalIdsByScanId(scanResultId: Long): List<Long>

    @Query(
        "SELECT id FROM forensic_timeline WHERE kind = 'signal' AND persistent = 0 AND (scanResultId = -1 OR " +
            "NOT EXISTS (SELECT 1 FROM ScanResult s WHERE s.id = forensic_timeline.scanResultId))"
    )
    suspend fun signalIdsUnownedNonPersistent(): List<Long>

    @Query(
        "SELECT DISTINCT recordId FROM forensic_timeline " +
            "WHERE createdAt < :cutoff AND persistent = 0 AND recordId IS NOT NULL"
    )
    suspend fun recordIdsOlderThan(cutoff: Long): List<Long>

    /** The rows [ids] (the one-time legacy event-row cleanup, C3). At most 900 ids per call. */
    @Query("DELETE FROM forensic_timeline WHERE id IN (:ids)")
    suspend fun deleteByIds(ids: List<Long>)

    @Query("SELECT DISTINCT recordId FROM forensic_timeline WHERE id IN (:ids) AND recordId IS NOT NULL")
    suspend fun recordIdsByIds(ids: List<Long>): List<Long>

    /** A scan's own rows; persistent (audit/closure) rows survive scan deletion (spec §5.1). */
    @Query("DELETE FROM forensic_timeline WHERE scanResultId = :scanResultId AND persistent = 0")
    suspend fun deleteByScanId(scanResultId: Long)

    @Query(
        "SELECT DISTINCT recordId FROM forensic_timeline " +
            "WHERE scanResultId = :scanResultId AND persistent = 0 AND recordId IS NOT NULL"
    )
    suspend fun recordIdsByScanId(scanResultId: Long): List<Long>

    /** "Clear all": non-persistent rows that are scan-less or whose scan no longer exists. */
    @Query(
        "DELETE FROM forensic_timeline WHERE persistent = 0 AND (scanResultId = -1 OR NOT EXISTS " +
            "(SELECT 1 FROM ScanResult s WHERE s.id = forensic_timeline.scanResultId))"
    )
    suspend fun deleteUnownedNonPersistent()

    @Query(
        "SELECT DISTINCT recordId FROM forensic_timeline WHERE persistent = 0 AND recordId IS NOT NULL " +
            "AND (scanResultId = -1 OR NOT EXISTS " +
            "(SELECT 1 FROM ScanResult s WHERE s.id = forensic_timeline.scanResultId))"
    )
    suspend fun recordIdsUnownedNonPersistent(): List<Long>

    /**
     * Of [recordIds], the `(ruleId, recordId)` pairs a visible finding row already carries — the
     * Phase A–C late-IOC re-check emits a finding only when none exists (spec §5.2).
     */
    @Query(
        "SELECT r.ruleId AS ruleId, r.recordId AS recordId FROM forensic_timeline r " +
            "WHERE r.recordId IN (:recordIds) AND r.ruleId != '' AND ${VisibleRow.SQL}"
    )
    suspend fun findingRuleRecords(recordIds: List<Long>): List<RuleRecord>
}
