package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Query
import com.androdr.data.model.Alert

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

    /** Of [keys], those that already have an alert. */
    @Query("SELECT alertKey FROM alert WHERE alertKey IN (:keys)")
    suspend fun existingKeys(keys: List<ByteArray>): List<ByteArray>

    @Query("$OPEN_ALERT_COUNT")
    suspend fun openCount(): Int

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

    /** Bytes of every alert's evidence JSON (alerts are never deleted; the Settings storage figure). */
    @Query("SELECT COALESCE(SUM(LENGTH(evidenceJson)), 0) FROM alert")
    suspend fun evidenceBytes(): Long
}

// Statements [AlertDao] shares with the query-plan gate (FindingQueryPlanTest).

/**
 * Opens one alert per new key among a scan's findings (spec §5.2 finish), from the rows that carry
 * opening evidence (a key that already has an alert is ignored). Rows are read in the
 * `(scanId, alertKey)` index's order — by key, then by id — so the first row per key wins without a
 * sort.
 */
internal const val OPEN_ALERTS_FOR_SCAN = "INSERT OR IGNORE INTO alert (alertKey, ruleId, status, openedAt, " +
    "openedScanId, lastActivityAt, closedAt, closedReason, closedWithCredential, level, recordId, evidenceJson) " +
    "SELECT sf.alertKey, sf.ruleId, 'OPEN', :openedAt, sf.scanId, :openedAt, NULL, NULL, 0, sf.level, " +
    "sf.recordId, sf.evidenceJson FROM scan_finding sf WHERE sf.scanId = :scanId " +
    "AND sf.alertKey IS NOT NULL AND sf.evidenceJson IS NOT NULL ORDER BY sf.alertKey, sf.id"

/** Attaches every keyed finding of a scan to its alert (by the unique `alertKey` index). */
internal const val ATTACH_ALERTS_FOR_SCAN = "UPDATE scan_finding SET alertId = (SELECT a.id FROM alert a " +
    "WHERE a.alertKey = scan_finding.alertKey) WHERE scanId = :scanId AND alertKey IS NOT NULL"

/** Re-surfaces every alert a finding of a scan attached to (a closed alert stays closed). */
internal const val TOUCH_ALERTS_FOR_SCAN = "UPDATE alert SET lastActivityAt = :at WHERE lastActivityAt < :at " +
    "AND id IN (SELECT sf.alertId FROM scan_finding sf WHERE sf.scanId = :scanId AND sf.alertKey IS NOT NULL)"

/** How many alerts are OPEN (the dashboard's count, with the state findings). */
internal const val OPEN_ALERT_COUNT = "SELECT COUNT(*) FROM alert WHERE status = 'OPEN'"

/** Keyset page of OPEN alerts, most recent activity first (`(lastActivityAt, id)` descending). */
internal const val OPEN_ALERTS_AFTER = "SELECT * FROM alert WHERE status = 'OPEN' AND (lastActivityAt < :at OR " +
    "(lastActivityAt = :at AND id < :id)) ORDER BY lastActivityAt DESC, id DESC LIMIT :size"
