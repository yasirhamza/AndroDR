package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Query
import com.androdr.data.model.Alert

/** One alert group as the report prints it: counts, first opening, latest activity and closing. */
data class AlertReportGroupRow(
    val ruleId: String,
    val matchedValue: String,
    val count: Int,
    val lastActivityAt: Long,
    val firstOpenedAt: Long,
    val lastClosedAt: Long?,
    val withCredential: Int,
)

/** An alert's key and id. Plain: holds a `ByteArray`. */
class AlertKeyId(val key: ByteArray, val id: Long)

/**
 * One group of OPEN alerts (spec §5.4: the list groups by rule and matched value): how many, the
 * latest activity among them (the group re-surfaces with it) and the newest alert's id, which also
 * bounds a group close to the alerts the person saw.
 */
data class AlertGroupRow(
    val ruleId: String,
    val matchedValue: String,
    val count: Int,
    val lastActivityAt: Long,
    val maxId: Long,
)

/**
 * `alert` (spec §5.4): created set-based in a session's finishing transaction from that scan's
 * `scan_finding.alertKey` values, never deleted. List-parameter queries go through [chunkedIn].
 */
@Dao
@Suppress("TooManyFunctions") // Room DAO: the finishing transaction's statements and the readers'
interface AlertDao {

    @Query("$OPEN_ALERTS_FOR_SCAN")
    suspend fun openForScan(scanId: Long, openedAt: Long)

    @Query("$ATTACH_ALERTS_FOR_SCAN")
    suspend fun attachForScan(scanId: Long)

    @Query("$TOUCH_ALERTS_FOR_SCAN")
    suspend fun touchForScan(scanId: Long, at: Long)

    /** Of [keys], those that already have an alert, with its id. */
    @Query("SELECT alertKey AS `key`, id FROM alert WHERE alertKey IN (:keys)")
    suspend fun idsForKeys(keys: List<ByteArray>): List<AlertKeyId>

    @Query("$OPEN_ALERT_COUNT")
    suspend fun openCount(): Int

    /** The distinct levels of OPEN alerts (the Dashboard's highest open level; index `(status, level)`). */
    @Query("$OPEN_ALERT_LEVELS")
    suspend fun openLevels(): List<String>

    /** Keyset page of alert groups with [status] for the report ([ALERT_REPORT_GROUPS_AFTER]). */
    @Query("$ALERT_REPORT_GROUPS_AFTER")
    suspend fun reportGroupsAfter(
        status: String, at: Long, ruleId: String, value: String, size: Int,
    ): List<AlertReportGroupRow>

    /** Up to [size] alerts of one group, most recent activity first (the report's sample). */
    @Query("$ALERT_GROUP_SAMPLE")
    suspend fun groupSample(status: String, ruleId: String, value: String, size: Int): List<Alert>

    @Query("$OPEN_ALERTS_AFTER")
    suspend fun openAfter(at: Long, id: Long, size: Int): List<Alert>

    /** The prepend query of [openAfter]: OPEN alerts after `(at, id)`, nearest first. */
    @Query(
        "SELECT * FROM alert WHERE status = 'OPEN' AND (lastActivityAt > :at OR (lastActivityAt = :at " +
            "AND id > :id)) ORDER BY lastActivityAt ASC, id ASC LIMIT :size"
    )
    suspend fun openBefore(at: Long, id: Long, size: Int): List<Alert>

    /** Closes the OPEN alerts among [ids]; returns how many changed. */
    @Query(
        "UPDATE alert SET status = 'CLOSED', closedAt = :at, closedReason = :reason, " +
            "closedWithCredential = :withCredential WHERE id IN (:ids) AND status = 'OPEN'"
    )
    suspend fun closeOpen(ids: List<Long>, at: Long, reason: String?, withCredential: Boolean): Int

    @Query("SELECT * FROM alert WHERE id IN (:ids)")
    suspend fun alertsByIds(ids: List<Long>): List<Alert>

    /** Keyset page of OPEN-alert groups ([OPEN_ALERT_GROUPS_AFTER]). */
    @Query("$OPEN_ALERT_GROUPS_AFTER")
    suspend fun openGroupsAfter(at: Long, ruleId: String, value: String, size: Int): List<AlertGroupRow>

    /** [openGroupsAfter], inclusive of `(at, ruleId, value)` (a refresh). */
    @Query(
        "SELECT ruleId, matchedValue, COUNT(*) AS count, MAX(lastActivityAt) AS lastActivityAt, MAX(id) AS maxId " +
            "FROM alert WHERE status = 'OPEN' GROUP BY ruleId, matchedValue HAVING MAX(lastActivityAt) < :at OR " +
            "(MAX(lastActivityAt) = :at AND (ruleId > :ruleId OR (ruleId = :ruleId AND matchedValue >= :value))) " +
            "ORDER BY lastActivityAt DESC, ruleId ASC, matchedValue ASC LIMIT :size"
    )
    suspend fun openGroupsFrom(at: Long, ruleId: String, value: String, size: Int): List<AlertGroupRow>

    /** The prepend query of [openGroupsAfter]: groups before `(at, ruleId, value)` in list order, nearest first. */
    @Query(
        "SELECT ruleId, matchedValue, COUNT(*) AS count, MAX(lastActivityAt) AS lastActivityAt, MAX(id) AS maxId " +
            "FROM alert WHERE status = 'OPEN' GROUP BY ruleId, matchedValue HAVING MAX(lastActivityAt) > :at OR " +
            "(MAX(lastActivityAt) = :at AND (ruleId < :ruleId OR (ruleId = :ruleId AND matchedValue < :value))) " +
            "ORDER BY lastActivityAt ASC, ruleId DESC, matchedValue DESC LIMIT :size"
    )
    suspend fun openGroupsBefore(at: Long, ruleId: String, value: String, size: Int): List<AlertGroupRow>

    /** The OPEN-alert groups among [ids] (a close's audit text). Call through [chunkedIn]. */
    @Query(
        "SELECT ruleId, matchedValue, COUNT(*) AS count, MAX(lastActivityAt) AS lastActivityAt, MAX(id) AS maxId " +
            "FROM alert WHERE id IN (:ids) AND status = 'OPEN' GROUP BY ruleId, matchedValue"
    )
    suspend fun openGroupsOf(ids: List<Long>): List<AlertGroupRow>

    /** Closes one group's OPEN alerts up to [maxId] (those the person saw); returns how many changed. */
    @Query("$CLOSE_ALERT_GROUP")
    suspend fun closeGroup(
        ruleId: String, value: String, maxId: Long, at: Long, reason: String?, withCredential: Boolean,
    ): Int

    /** The OPEN alerts of one finding row: its rule on its fact (a Timeline row's Close). */
    @Query("SELECT id FROM alert WHERE recordId = :recordId AND ruleId = :ruleId AND status = 'OPEN'")
    suspend fun openIdsFor(ruleId: String, recordId: Long): List<Long>

    /** Bytes of every alert's evidence JSON (alerts are never deleted; the Settings storage figure). */
    @Query("SELECT COALESCE(SUM(LENGTH(evidenceJson)), 0) FROM alert")
    suspend fun evidenceBytes(): Long
}

// Statements [AlertDao] shares with the query-plan gate (FindingQueryPlanTest).

/**
 * Opens one alert per new key among a scan's findings (spec §5.2 finish), from the rows that carry
 * opening evidence — a fact row's transient `evidenceJson`, or a no-fact row's own `findingJson`,
 * which keeps its `matchContext` (a key that already has an alert is ignored). Rows are read in the
 * `(scanId, alertKey)` index's order — by key, then by id — so the first row per key wins without a
 * sort.
 */
internal const val OPEN_ALERTS_FOR_SCAN = "INSERT OR IGNORE INTO alert (alertKey, ruleId, status, openedAt, " +
    "openedScanId, lastActivityAt, closedAt, closedReason, closedWithCredential, level, recordId, evidenceJson, " +
    "matchedValue) SELECT sf.alertKey, sf.ruleId, 'OPEN', :openedAt, sf.scanId, :openedAt, NULL, NULL, 0, sf.level, " +
    "sf.recordId, COALESCE(sf.evidenceJson, sf.findingJson), COALESCE(sf.matchedValue, '') " +
    "FROM scan_finding sf WHERE sf.scanId = :scanId " +
    "AND sf.alertKey IS NOT NULL AND sf.alertId IS NULL AND (sf.evidenceJson IS NOT NULL OR sf.recordId IS NULL) " +
    "ORDER BY sf.alertKey, sf.id"

/**
 * Attaches every keyed finding of a scan that is not attached yet (rows whose key already had an
 * alert were attached at insert) to its alert (by the unique `alertKey` index).
 */
internal const val ATTACH_ALERTS_FOR_SCAN = "UPDATE scan_finding SET alertId = (SELECT a.id FROM alert a " +
    "WHERE a.alertKey = scan_finding.alertKey) WHERE scanId = :scanId AND alertKey IS NOT NULL AND alertId IS NULL"

/** Re-surfaces every alert a finding of a scan attached to (a closed alert stays closed). */
internal const val TOUCH_ALERTS_FOR_SCAN = "UPDATE alert SET lastActivityAt = :at WHERE lastActivityAt < :at " +
    "AND id IN (SELECT sf.alertId FROM scan_finding sf WHERE sf.scanId = :scanId AND sf.alertKey IS NOT NULL)"

/** How many alerts are OPEN (the dashboard's count, with the state findings). */
internal const val OPEN_ALERT_COUNT = "SELECT COUNT(*) FROM alert WHERE status = 'OPEN'"

/** Keyset page of OPEN alerts, most recent activity first (`(lastActivityAt, id)` descending). */
internal const val OPEN_ALERTS_AFTER = "SELECT * FROM alert WHERE status = 'OPEN' AND (lastActivityAt < :at OR " +
    "(lastActivityAt = :at AND id < :id)) ORDER BY lastActivityAt DESC, id DESC LIMIT :size"

/**
 * Keyset page of OPEN-alert groups by rule and matched value (spec §5.4), most recent activity first,
 * then by rule and value: `(lastActivityAt DESC, ruleId, matchedValue)`. The grouping walks index
 * `(status, ruleId, matchedValue, lastActivityAt)` without a sort; ordering the groups needs one, over
 * groups only (bounded by distinct rule × indicator pairs, not by alerts).
 */
internal const val OPEN_ALERT_GROUPS_AFTER = "SELECT ruleId, matchedValue, COUNT(*) AS count, " +
    "MAX(lastActivityAt) AS lastActivityAt, MAX(id) AS maxId FROM alert WHERE status = 'OPEN' " +
    "GROUP BY ruleId, matchedValue HAVING MAX(lastActivityAt) < :at OR (MAX(lastActivityAt) = :at AND " +
    "(ruleId > :ruleId OR (ruleId = :ruleId AND matchedValue > :value))) " +
    "ORDER BY lastActivityAt DESC, ruleId ASC, matchedValue ASC LIMIT :size"

/** Closes one group's OPEN alerts up to `maxId` (index `(status, ruleId, matchedValue, …)`). */
internal const val CLOSE_ALERT_GROUP = "UPDATE alert SET status = 'CLOSED', closedAt = :at, closedReason = :reason, " +
    "closedWithCredential = :withCredential WHERE status = 'OPEN' AND ruleId = :ruleId " +
    "AND matchedValue = :value AND id <= :maxId"

/** The levels of OPEN alerts (index `(status, level)`: a covering search, no row reads). */
internal const val OPEN_ALERT_LEVELS = "SELECT DISTINCT level FROM alert WHERE status = 'OPEN'"

/**
 * The report's alert groups with one status, in the Dashboard's order and grouping (spec §5.4, review
 * I5): `(lastActivityAt DESC, ruleId, matchedValue)`, keyset by HAVING. Ordering the groups sorts
 * groups only.
 */
internal const val ALERT_REPORT_GROUPS_AFTER = "SELECT ruleId, matchedValue, COUNT(*) AS count, " +
    "MAX(lastActivityAt) AS lastActivityAt, MIN(openedAt) AS firstOpenedAt, MAX(closedAt) AS lastClosedAt, " +
    "COALESCE(SUM(closedWithCredential), 0) AS withCredential FROM alert WHERE status = :status " +
    "GROUP BY ruleId, matchedValue HAVING MAX(lastActivityAt) < :at OR (MAX(lastActivityAt) = :at AND " +
    "(ruleId > :ruleId OR (ruleId = :ruleId AND matchedValue > :value))) " +
    "ORDER BY lastActivityAt DESC, ruleId ASC, matchedValue ASC LIMIT :size"

/** A group's most recent alerts (index `(status, ruleId, matchedValue, lastActivityAt)`, no sort). */
internal const val ALERT_GROUP_SAMPLE = "SELECT * FROM alert WHERE status = :status AND ruleId = :ruleId " +
    "AND matchedValue = :value ORDER BY lastActivityAt DESC, id DESC LIMIT :size"
