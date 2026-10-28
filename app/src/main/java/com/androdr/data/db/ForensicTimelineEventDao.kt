package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.ForensicTimelineEvent

@Dao
@Suppress("TooManyFunctions") // Room DAO: the writers', deleters' and pin readers' queries
interface ForensicTimelineEventDao {

    // Reads below show only visible rows (spec §5.1 Visibility: `VisibleRow`), so rows of an
    // IN_PROGRESS or DELETING scan never reach a report or an export. The Timeline reads through
    // TimelineDao (spec §6: the keyset union of event facts and rows).

    @Query("SELECT DISTINCT r.source FROM forensic_timeline r WHERE ${VisibleRow.SQL} ORDER BY r.source")
    suspend fun getDistinctSources(): List<String>

    @Query("SELECT DISTINCT packageName FROM forensic_timeline WHERE category = 'package_install'")
    suspend fun getInstalledPackagesAlreadyEmitted(): List<String>

    @Query("SELECT DISTINCT packageName FROM forensic_timeline WHERE category = 'device_admin_grant'")
    suspend fun getAdminGrantedPackagesAlreadyEmitted(): List<String>

    /** Up to [size] visible rows with `id > afterId`, ascending by id (keyset; the STIX export streams it). */
    @Query("SELECT * FROM forensic_timeline r WHERE r.id > :afterId AND ${VisibleRow.SQL} ORDER BY r.id LIMIT :size")
    suspend fun visibleAfter(afterId: Long, size: Int): List<ForensicTimelineEvent>

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
        "SELECT id FROM forensic_timeline WHERE kind = 'signal' AND persistent = 0 AND scanResultId = -1 " +
            "AND id <= :maxId"
    )
    suspend fun signalIdsScanLessThrough(maxId: Long): List<Long>

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

    /**
     * "Clear all" (spec §5.4): the non-persistent scan-less rows (`scanResultId = -1`, live
     * `dns_query`/`ioc_match` rows among them) that existed at its first transaction (`id <= maxId`).
     * A row written after that, or a row of a scan begun after it, is untouched.
     */
    @Query("$DELETE_SCAN_LESS_THROUGH")
    suspend fun deleteScanLessThrough(maxId: Long)

    @Query(
        "SELECT DISTINCT recordId FROM forensic_timeline WHERE persistent = 0 AND recordId IS NOT NULL " +
            "AND scanResultId = -1 AND id <= :maxId"
    )
    suspend fun recordIdsScanLessThrough(maxId: Long): List<Long>

    /** The newest row id ("Clear all"'s `clearMaxRowId`); 0 when the table is empty. */
    @Query("SELECT COALESCE(MAX(id), 0) FROM forensic_timeline")
    suspend fun maxId(): Long
}

/** "Clear all"'s scan-less delete (index `(scanResultId, startTimestamp)`). */
internal const val DELETE_SCAN_LESS_THROUGH =
    "DELETE FROM forensic_timeline WHERE persistent = 0 AND scanResultId = -1 AND id <= :maxId"
