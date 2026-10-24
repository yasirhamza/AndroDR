package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.androdr.data.model.ScanFinding

/** One stored finding as a reader needs it (no Timeline row columns, no transient evidence). */
@Suppress("LongParameterList")
class FindingRow(
    val id: Long,
    val scanId: Long,
    val ruleId: String,
    val triggered: Boolean,
    val level: String,
    val kind: String,
    val recordId: Long?,
    val alertId: Long?,
    val findingJson: String,
)

/** How many triggered findings one rule has in a scan. */
data class RuleCount(val ruleId: String, val count: Int)

/** A scan's triggered-finding counts the History sheet shows (spec §7), computed in SQL. */
data class FindingSummaryCounts(val appIssues: Int, val deviceIssues: Int, val warningSigns: Int)

/**
 * `scan_finding` (spec §5.4). Writer statements run in a session's transactions; every read requires
 * the finding's scan to be `COMPLETE` ([CompleteScan], spec §5.1 Visibility). List-parameter
 * queries go through [chunkedIn].
 */
@Dao
@Suppress("TooManyFunctions") // Room DAO: the writer's, the deleter's and the readers' statements
interface ScanFindingDao {

    @Insert
    suspend fun insertAll(rows: List<ScanFinding>): List<Long>

    /**
     * This scan's finding rows (spec §5.2 finish): one `INSERT … SELECT` from its triggered findings'
     * precomputed Timeline columns, in recording order. Correlation findings carry no row columns
     * (their Timeline row is the signal).
     */
    @Query("$INSERT_FINDING_ROWS")
    suspend fun insertFindingRows(scanId: Long, createdAt: Long)

    /** Clears the transient opening evidence once this scan's alerts exist. */
    @Query("UPDATE scan_finding SET evidenceJson = NULL WHERE scanId = :scanId AND evidenceJson IS NOT NULL")
    suspend fun clearEvidence(scanId: Long)

    /** Rows of [scanId] with an alert key and no alert: must be 0 after `finish` attaches them. */
    @Query("SELECT COUNT(*) FROM scan_finding WHERE scanId = :scanId AND alertKey IS NOT NULL AND alertId IS NULL")
    suspend fun unattachedCount(scanId: Long): Int

    /**
     * The facts a scan's late-IOC re-check findings (`ordinal < 0`) pin: facts it did not observe, so
     * deleting its observations would never release them. Read before [deleteBatchForScan] (review
     * Minor 8); the facts it observed are released batch by batch with its observations.
     */
    @Query(
        "SELECT DISTINCT recordId FROM scan_finding WHERE scanId = :scanId AND triggered = 1 " +
            "AND ordinal < 0 AND recordId IS NOT NULL"
    )
    suspend fun recheckRecordIdsForScan(scanId: Long): List<Long>

    /** Deletes up to [size] of a scan's findings (one batch, any order); returns how many went. */
    @Query("$DELETE_FINDINGS_BATCH")
    suspend fun deleteBatchForScan(scanId: Long, size: Int): Int

    /** Keyset page of one COMPLETE scan's findings with [triggered], by id. */
    @Query("$FINDINGS_PAGE")
    suspend fun page(scanId: Long, triggered: Boolean, afterId: Long, size: Int): List<FindingRow>

    /** The prepend query of [page]: ids below [beforeId], descending. */
    @Query(
        "SELECT sf.id, sf.scanId, sf.ruleId, sf.triggered, sf.level, sf.kind, sf.recordId, sf.alertId, " +
            "sf.findingJson FROM scan_finding sf JOIN ScanResult s ON s.id = sf.scanId " +
            "WHERE sf.scanId = :scanId AND sf.triggered = :triggered AND sf.id < :beforeId " +
            "AND ${CompleteScan.SQL} ORDER BY sf.id DESC LIMIT :size"
    )
    suspend fun pageBefore(scanId: Long, triggered: Boolean, beforeId: Long, size: Int): List<FindingRow>

    /**
     * The current state findings (spec §5.4 Lifecycle): the newest COMPLETE live scan's triggered
     * STATE findings. Bounded by rules × live records.
     */
    @Query("$CURRENT_STATE")
    suspend fun currentState(): List<FindingRow>

    /** Triggered findings of a COMPLETE scan, informational ones excluded (the import screen's count). */
    @Query(
        "SELECT COUNT(*) FROM scan_finding sf JOIN ScanResult s ON s.id = sf.scanId " +
            "WHERE sf.scanId = :scanId AND sf.triggered = 1 AND lower(sf.level) != 'informational' " +
            "AND ${CompleteScan.SQL}"
    )
    suspend fun triggeredShownCount(scanId: Long): Int

    /** A COMPLETE scan's triggered findings per rule (bounded by the rule count): the diff's input. */
    @Query("$TRIGGERED_RULE_COUNTS")
    suspend fun triggeredRuleCounts(scanId: Long): List<RuleCount>

    /** Up to [size] of a COMPLETE scan's triggered findings of one rule, in recording order (a diff's sample). */
    @Query("$RULE_SAMPLE")
    suspend fun ruleSample(scanId: Long, ruleId: String, size: Int): List<FindingRow>

    /** The History sheet's counts: triggered app issues (informational excluded), device issues, warning signs. */
    @Query("$SUMMARY_COUNTS")
    suspend fun summaryCounts(scanId: Long): FindingSummaryCounts
}

// Statements [ScanFindingDao] shares with the query-plan gate (FindingQueryPlanTest), so the plan is
// checked on the exact SQL Room runs.

/**
 * This scan's finding rows (spec §5.2 finish): one `INSERT … SELECT` from its triggered findings'
 * precomputed Timeline columns, in recording order (index `(scanId, triggered)`, rowid order).
 * Correlation findings carry no row columns (their Timeline row is the signal).
 */
internal const val INSERT_FINDING_ROWS = "INSERT INTO forensic_timeline (startTimestamp, kind, " +
    "timestampPrecision, source, category, description, details, packageName, appName, processUid, iocIndicator, " +
    "iocType, iocSource, campaignName, apkHash, correlationId, ruleId, scanResultId, attackTechniqueId, " +
    "telemetrySource, createdAt, recordId, level, persistent) " +
    "SELECT sf.row_startTimestamp, 'event', sf.row_timestampPrecision, sf.row_source, sf.row_category, " +
    "sf.row_description, sf.row_details, sf.row_packageName, sf.row_appName, -1, sf.row_iocIndicator, " +
    "sf.row_iocType, sf.row_iocSource, sf.row_campaignName, sf.row_apkHash, sf.row_correlationId, " +
    "sf.ruleId, sf.scanId, sf.row_attackTechniqueId, sf.row_telemetrySource, :createdAt, sf.recordId, " +
    "sf.level, 0 FROM scan_finding sf WHERE sf.scanId = :scanId AND sf.triggered = 1 " +
    "AND sf.row_source IS NOT NULL ORDER BY sf.id"

/** Keyset page of one COMPLETE scan's findings with `triggered`, by id. */
internal const val FINDINGS_PAGE = "SELECT sf.id, sf.scanId, sf.ruleId, sf.triggered, sf.level, sf.kind, " +
    "sf.recordId, sf.alertId, sf.findingJson FROM scan_finding sf JOIN ScanResult s ON s.id = sf.scanId " +
    "WHERE sf.scanId = :scanId AND sf.triggered = :triggered AND sf.id > :afterId " +
    "AND ${CompleteScan.SQL} ORDER BY sf.id LIMIT :size"

/** Up to `size` of a COMPLETE scan's triggered findings of one rule, in recording order (a diff's sample). */
internal const val RULE_SAMPLE = "SELECT sf.id, sf.scanId, sf.ruleId, sf.triggered, sf.level, sf.kind, " +
    "sf.recordId, sf.alertId, sf.findingJson FROM scan_finding sf JOIN ScanResult s ON s.id = sf.scanId " +
    "WHERE sf.scanId = :scanId AND sf.triggered = 1 AND sf.ruleId = :ruleId AND ${CompleteScan.SQL} " +
    "ORDER BY sf.id LIMIT :size"

/** One delete batch of a scan's findings; no order is needed, so it is an index range read. */
internal const val DELETE_FINDINGS_BATCH = "DELETE FROM scan_finding WHERE id IN (SELECT id FROM scan_finding " +
    "WHERE scanId = :scanId LIMIT :size)"

/** Triggered findings per rule of one COMPLETE scan (index `(scanId, triggered)`). */
internal const val TRIGGERED_RULE_COUNTS = "SELECT sf.ruleId AS ruleId, COUNT(*) AS count FROM scan_finding sf " +
    "JOIN ScanResult s ON s.id = sf.scanId WHERE sf.scanId = :scanId AND sf.triggered = 1 " +
    "AND ${CompleteScan.SQL} GROUP BY sf.ruleId"

/** The History sheet's counts, by display category (index `(scanId, triggered)`). */
internal const val SUMMARY_COUNTS = "SELECT " +
    "COALESCE(SUM(CASE WHEN sf.category = 'APP_RISK' AND lower(sf.level) != 'informational' THEN 1 ELSE 0 END), 0) " +
    "AS appIssues, COALESCE(SUM(CASE WHEN sf.category = 'DEVICE_POSTURE' THEN 1 ELSE 0 END), 0) AS deviceIssues, " +
    "COALESCE(SUM(CASE WHEN sf.category = 'CORRELATION' THEN 1 ELSE 0 END), 0) AS warningSigns " +
    "FROM scan_finding sf JOIN ScanResult s ON s.id = sf.scanId WHERE sf.scanId = :scanId " +
    "AND sf.triggered = 1 AND ${CompleteScan.SQL}"

/**
 * The current state findings (spec §5.4 Lifecycle): the newest COMPLETE live scan's triggered
 * STATE findings. Bounded by rules × live records.
 */
internal const val CURRENT_STATE = "SELECT sf.id, sf.scanId, sf.ruleId, sf.triggered, sf.level, sf.kind, " +
    "sf.recordId, sf.alertId, sf.findingJson FROM scan_finding sf JOIN ScanResult s ON s.id = sf.scanId " +
    "WHERE sf.scanId = ($LATEST_LIVE_ID) AND sf.triggered = 1 AND sf.kind = 'STATE' " +
    "AND ${CompleteScan.SQL} ORDER BY sf.id"
