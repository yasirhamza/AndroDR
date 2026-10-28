package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.SignalMember

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

    /**
     * The 30-day prune's non-signal rows ([PRUNABLE], spec §5.6): only non-persistent `LIVE_SCAN`
     * rows that no surviving signal's `signal_member` row ref points at. Its signal rows go by id
     * ([signalIdsOlderThan], [deleteByIds]) with their members.
     */
    @Query("$PRUNE_DELETE")
    suspend fun deleteOlderThan(cutoff: Long)

    // The signal rows each delete below is about to remove: their `signal_member` rows go with
    // them, by id (TimelineRowDeleter; spec §5.4). Same predicates as the paired deletes.

    /** The prune's signal rows ([PRUNABLE]: a signal another signal lists as a member stays). */
    @Query("$PRUNE_SIGNAL_IDS")
    suspend fun signalIdsOlderThan(cutoff: Long): List<Long>

    @Query("SELECT id FROM forensic_timeline WHERE kind = 'signal' AND id IN (:ids)")
    suspend fun signalIdsByIds(ids: List<Long>): List<Long>

    @Query("SELECT id FROM forensic_timeline WHERE kind = 'signal' AND scanResultId = :scanResultId AND persistent = 0")
    suspend fun signalIdsByScanId(scanResultId: Long): List<Long>

    @Query(
        "SELECT id FROM forensic_timeline WHERE kind = 'signal' AND persistent = 0 AND id <= :maxId " +
            "AND (scanResultId = -1 $SCAN_GONE)"
    )
    suspend fun signalIdsScanLessThrough(maxId: Long): List<Long>

    /** The pins of [deleteOlderThan]'s rows (same predicate; read after the pruned signals' members go). */
    @Query("$PRUNE_RECORD_IDS")
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
            "AND id <= :maxId AND (scanResultId = -1 $SCAN_GONE)"
    )
    suspend fun recordIdsScanLessThrough(maxId: Long): List<Long>

    /** The newest row id ("Clear all"'s `clearMaxRowId`); 0 when the table is empty. */
    @Query("SELECT COALESCE(MAX(id), 0) FROM forensic_timeline")
    suspend fun maxId(): Long
}

/**
 * Rows of a scan that no longer exists (left over from before Phase D). Safe in "Clear all" because
 * the rows of any scan begun after its first transaction have `id > maxId` (review m5).
 */
internal const val SCAN_GONE = "OR (scanResultId != -1 AND NOT EXISTS " +
    "(SELECT 1 FROM ScanResult s WHERE s.id = forensic_timeline.scanResultId))"

/**
 * The 30-day prune's rows (spec §5.6): non-persistent `LIVE_SCAN` rows created before `:cutoff`,
 * whatever their `scanResultId`, that no `signal_member` row ref points at. Run after the pruned
 * signals' members are deleted, so the refs left are those of surviving signals. A signal's ref to
 * itself does not exempt it.
 */
internal const val PRUNABLE = "createdAt < :cutoff AND persistent = 0 AND telemetrySource = 'LIVE_SCAN' " +
    "AND NOT EXISTS (SELECT 1 FROM signal_member m WHERE m.kind = ${SignalMember.KIND_ROW} " +
    "AND m.refId = forensic_timeline.id AND m.signalRowId != forensic_timeline.id)"

/** The prune's signal rows: deleted by id, together with their members (TimelineRowDeleter). */
internal const val PRUNE_SIGNAL_IDS = "SELECT id FROM forensic_timeline WHERE kind = 'signal' AND $PRUNABLE"

/** The pins of the prune's other rows, read just before [PRUNE_DELETE]. */
internal const val PRUNE_RECORD_IDS = "SELECT recordId FROM forensic_timeline " +
    "WHERE kind != 'signal' AND recordId IS NOT NULL AND $PRUNABLE"

/** The prune's other rows; signal rows are never deleted here (only by id, with their members). */
internal const val PRUNE_DELETE = "DELETE FROM forensic_timeline WHERE kind != 'signal' AND $PRUNABLE"

/** "Clear all"'s delete: scan-less rows and leftover rows of gone scans, up to `maxId`. */
internal const val DELETE_SCAN_LESS_THROUGH =
    "DELETE FROM forensic_timeline WHERE persistent = 0 AND id <= :maxId AND (scanResultId = -1 $SCAN_GONE)"
