package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Query
import com.androdr.data.model.TelemetrySource

/** One correlation atom as read from the database (see `AtomReader`). */
data class AtomRow(
    val id: Long,
    val category: String,
    val timestamp: Long,
    val packageName: String,
    val ruleId: String,
    val telemetrySource: TelemetrySource,
)

/**
 * A fact (aliased `f`) not stood in for by a timeline row that is itself an atom: no row in an
 * atom-bound category carries its `recordId`, or a `sourceEventKey` equal to its `sourceKey`
 * (spec §5.2 Correlation inputs). Such a row is the event's atom, so the fact is left out and the
 * event binds once. Rows outside the atom categories (finding rows) never stand in for a fact.
 */
internal const val ATOM_UNREFERENCED_FACT =
    "NOT EXISTS (SELECT 1 FROM forensic_timeline x WHERE x.recordId = f.id AND x.category IN (:categories)) " +
        "AND (f.sourceKey IS NULL OR NOT EXISTS (SELECT 1 FROM forensic_timeline y " +
        "WHERE y.sourceEventKey = f.sourceKey AND y.category IN (:categories)))"

/** Exact-precision facts in an atom-bound category (spec §4.3 Gate K1: day precision never binds). */
internal const val ATOM_FACT_FILTER =
    "f.category IN (:categories) AND f.timePrecision = 'EXACT' AND f.eventTime IS NOT NULL"

internal const val ATOM_ROW_COLS = "r.id AS id, r.category AS category, r.startTimestamp AS timestamp, " +
    "r.packageName AS packageName, r.ruleId AS ruleId, r.telemetrySource AS telemetrySource"

internal const val ATOM_FACT_COLS = "f.id AS id, f.category AS category, f.eventTime AS timestamp, " +
    "COALESCE(f.packageName, '') AS packageName, '' AS ruleId"

/**
 * Correlation-atom reads (spec §5.2), run inside the finishing transaction. The current-scan reads
 * see the `IN_PROGRESS` scan's own rows and observations (allow-listed in the Q1 gate); the
 * lookback reads see only visible rows ([VisibleRow]) and facts a `COMPLETE` live scan observed,
 * so rows and facts of `IN_PROGRESS` or `DELETING` scans never bind, and imports never do.
 */
@Dao
interface AtomDao {

    @Query(
        "SELECT $ATOM_ROW_COLS FROM forensic_timeline r WHERE r.scanResultId = :scanId " +
            "AND r.category IN (:categories)"
    )
    suspend fun rowsForScan(scanId: Long, categories: List<String>): List<AtomRow>

    @Query(
        "SELECT $ATOM_FACT_COLS, o.source AS telemetrySource FROM scan_record o " +
            "JOIN telemetry_record f ON f.id = o.recordId WHERE o.scanId = :scanId AND $ATOM_FACT_FILTER " +
            "AND $ATOM_UNREFERENCED_FACT"
    )
    suspend fun factsForScan(scanId: Long, categories: List<String>): List<AtomRow>

    @Query(
        "SELECT $ATOM_ROW_COLS FROM forensic_timeline r WHERE r.startTimestamp BETWEEN :since AND :until " +
            "AND r.category IN (:categories) AND r.telemetrySource = 'LIVE_SCAN' AND ${VisibleRow.SQL}"
    )
    suspend fun liveRowsBetween(since: Long, until: Long, categories: List<String>): List<AtomRow>

    @Query(
        "SELECT $ATOM_FACT_COLS, 'LIVE_SCAN' AS telemetrySource FROM telemetry_record f " +
            "WHERE f.eventTime BETWEEN :since AND :until AND $ATOM_FACT_FILTER " +
            "AND EXISTS (SELECT 1 FROM scan_record o JOIN ScanResult s ON s.id = o.scanId " +
            "WHERE o.recordId = f.id AND s.state = 'COMPLETE' AND o.source = 'LIVE_SCAN') " +
            "AND $ATOM_UNREFERENCED_FACT"
    )
    suspend fun liveFactsBetween(since: Long, until: Long, categories: List<String>): List<AtomRow>
}
