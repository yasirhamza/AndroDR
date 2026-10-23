package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Query
import com.androdr.data.model.TelemetrySource

/**
 * One stored record as read back: the fact, its body and (for an observed fact) the observation.
 * A pinned orphan (no observation left, spec §5.1) has [scanId] and [ordinal] −1 and carries
 * the fact's first-observation envelope (`firstSource`, `firstCapturedAt`, `firstStrippedKeys`)
 * as [source], [capturedAt] and [strippedKeys]. Plain: holds a `ByteArray`.
 */
@Suppress("LongParameterList")
class StoredRecordRow(
    val factId: Long,
    val scanId: Long,
    val service: String,
    val ordinal: Int,
    val source: TelemetrySource,
    val capturedAt: Long,
    val strippedKeys: Int,
    val eventTime: Long?,
    val timePrecision: String,
    val category: String?,
    val subjectKey: String?,
    val encoding: Int,
    val dictVersion: Int,
    val body: ByteArray,
    val rawBytes: Int,
)

/** How many records one scan holds for one service. */
data class ServiceSummary(val service: String, val records: Int)

/**
 * One scan's record count, the decoded bytes of their bodies (an observed body counts per record),
 * and its latest exact event time.
 */
data class ScanTotals(val records: Long, val rawBytes: Long, val latestEventTime: Long?)

/** Distinct bodies of one encoding (−1 for the pinned-orphan total) and their sizes. */
data class BodyStatsRow(val encoding: Int, val bodies: Long, val storedBytes: Long, val rawBytes: Long)

/**
 * Reader side of the telemetry store (spec §5.1). Every query applies the visibility rule:
 * scan-scoped reads require their scan `COMPLETE` ([CompleteScan]); fact reads use
 * [VisibleFact] (a `COMPLETE` observation, or no observation and pinned). Paging is keyset on
 * `ordinal`, never OFFSET. List-parameter queries go through [chunkedIn].
 */
@Dao
@Suppress("TooManyFunctions") // Room DAO: one query per read the store's consumers need
interface TelemetryReadDao {

    /** The source that created visible fact [factId] (`firstSource`); null when it is not visible. */
    @Query("SELECT f.firstSource FROM telemetry_record f WHERE f.id = :factId AND ${VisibleFact.SQL}")
    suspend fun firstSource(factId: Long): TelemetrySource?

    /** The distinct sources of fact [factId]'s visible (`COMPLETE`) observations, by `scan_record(recordId)`. */
    @Query(
        "SELECT DISTINCT o.source FROM scan_record o JOIN ScanResult s ON s.id = o.scanId " +
            "WHERE o.recordId = :factId AND ${CompleteScan.SQL} ORDER BY o.source"
    )
    suspend fun observedSources(factId: Long): List<TelemetrySource>

    @Query(
        "SELECT o.service AS service, COUNT(*) AS records FROM scan_record o " +
            "JOIN ScanResult s ON s.id = o.scanId WHERE o.scanId = :scanId AND ${CompleteScan.SQL} " +
            "GROUP BY o.service ORDER BY o.service"
    )
    suspend fun services(scanId: Long): List<ServiceSummary>

    /** Records of one scan and service with `ordinal > after`, ascending. */
    @Query("SELECT $OBS_COLS $OBS_FROM WHERE o.scanId = :scanId AND o.service = :service " +
        "AND o.ordinal > :after AND ${CompleteScan.SQL} ORDER BY o.ordinal LIMIT :size")
    suspend fun pageAfter(scanId: Long, service: String, after: Int, size: Int): List<StoredRecordRow>

    /** Records of one scan and service with `ordinal < before`, DESCENDING (the prepend query). */
    @Query("SELECT $OBS_COLS $OBS_FROM WHERE o.scanId = :scanId AND o.service = :service " +
        "AND o.ordinal < :before AND ${CompleteScan.SQL} ORDER BY o.ordinal DESC LIMIT :size")
    suspend fun pageBefore(scanId: Long, service: String, before: Int, size: Int): List<StoredRecordRow>

    /**
     * Every visible record of a subject: its observations in COMPLETE scans and its pinned
     * orphans (read with their first observation's envelope), in one capture-time order
     * (`capturedAt`, then `scanId`, then `ordinal`; an orphan's `scanId` is −1).
     */
    @Query(
        "SELECT $OBS_COLS $OBS_FROM WHERE f.service = :service AND f.subjectKey = :subjectKey " +
            "AND ${CompleteScan.SQL} UNION ALL SELECT $ORPHAN_COLS FROM telemetry_record f " +
            "JOIN record_body b ON b.hash = f.bodyHash WHERE f.service = :service AND f.subjectKey = :subjectKey " +
            "AND ${VisibleFact.PINNED_ORPHAN} ORDER BY capturedAt, scanId, ordinal"
    )
    suspend fun history(service: String, subjectKey: String): List<StoredRecordRow>

    /**
     * Of [ids], the visible facts, each with its newest `COMPLETE` observation (or none, for a
     * pinned orphan, which reads with the fact's first-observation envelope). Call through [chunkedIn].
     */
    @Query(
        "SELECT f.id AS factId, COALESCE(o.scanId, -1) AS scanId, f.service AS service, " +
            "COALESCE(o.ordinal, -1) AS ordinal, COALESCE(o.source, f.firstSource) AS source, " +
            "COALESCE(o.capturedAt, f.firstCapturedAt) AS capturedAt, " +
            "COALESCE(o.strippedKeys, f.firstStrippedKeys) AS strippedKeys, $FACT_BODY_COLS FROM telemetry_record f " +
            "JOIN record_body b ON b.hash = f.bodyHash LEFT JOIN scan_record o ON o.recordId = f.id AND o.scanId = " +
            "(SELECT MAX(o2.scanId) FROM scan_record o2 JOIN ScanResult s2 ON s2.id = o2.scanId " +
            "WHERE o2.recordId = f.id AND s2.state = 'COMPLETE') WHERE f.id IN (:ids) AND ${VisibleFact.SQL}"
    )
    suspend fun records(ids: List<Long>): List<StoredRecordRow>

    /**
     * Records of [scanId] (COMPLETE) for [service] whose fact [otherScanId] (also COMPLETE) did
     * not observe, keyset on `ordinal`.
     */
    @Query(
        "SELECT $OBS_COLS $OBS_FROM WHERE o.scanId = :scanId AND o.service = :service " +
            "AND o.ordinal > :after AND ${CompleteScan.SQL} " +
            "AND EXISTS (SELECT 1 FROM ScanResult so WHERE so.id = :otherScanId AND so.state = 'COMPLETE') " +
            "AND NOT EXISTS (SELECT 1 FROM scan_record x WHERE x.scanId = :otherScanId AND x.recordId = o.recordId) " +
            "ORDER BY o.ordinal LIMIT :size"
    )
    suspend fun onlyIn(scanId: Long, otherScanId: Long, service: String, after: Int, size: Int): List<StoredRecordRow>

    /**
     * The late-IOC re-check's input (spec §5.2): facts of [service] with an event time at or after
     * [since] that a COMPLETE live scan observed — never an `IN_PROGRESS` scan's own facts, never an
     * import's — keyset on the fact id (`id > afterId`), each read with its first such observation.
     */
    @Query(
        "SELECT $OBS_COLS $OBS_FROM WHERE f.service = :service AND f.eventTime >= :since AND f.id > :afterId " +
            "AND o.source = 'LIVE_SCAN' AND ${CompleteScan.SQL} AND o.scanId = (SELECT MIN(o2.scanId) " +
            "FROM scan_record o2 JOIN ScanResult s2 ON s2.id = o2.scanId WHERE o2.recordId = f.id " +
            "AND o2.source = 'LIVE_SCAN' AND s2.state = 'COMPLETE') ORDER BY f.id LIMIT :size"
    )
    suspend fun liveFactsSince(service: String, since: Long, afterId: Long, size: Int): List<StoredRecordRow>

    /** The newest COMPLETE live scan that observed [service] at or after [since], if any. */
    @Query(
        "SELECT MAX(o.scanId) FROM scan_record o JOIN ScanResult s ON s.id = o.scanId " +
            "WHERE o.service = :service AND o.source = 'LIVE_SCAN' AND ${CompleteScan.SQL} AND o.capturedAt >= :since"
    )
    suspend fun latestLiveScan(service: String, since: Long): Long?

    /**
     * One COMPLETE scan's record count, the decoded size of their bodies, and the latest exact
     * event time among them no later than [eventsNotAfter] (null when no record has one).
     */
    @Query(
        "SELECT COUNT(*) AS records, COALESCE(SUM(b.rawBytes), 0) AS rawBytes, " +
            "MAX(CASE WHEN f.timePrecision = 'EXACT' AND f.eventTime <= :eventsNotAfter THEN f.eventTime END) " +
            "AS latestEventTime " +
            "$OBS_FROM WHERE o.scanId = :scanId AND ${CompleteScan.SQL}"
    )
    suspend fun scanTotals(scanId: Long, eventsNotAfter: Long = Long.MAX_VALUE): ScanTotals

    /** Distinct bodies of facts observed by a COMPLETE scan, by encoding. */
    @Query(
        "SELECT b.encoding AS encoding, COUNT(*) AS bodies, COALESCE(SUM(LENGTH(b.body)), 0) AS storedBytes, " +
            "COALESCE(SUM(b.rawBytes), 0) AS rawBytes FROM record_body b WHERE EXISTS (SELECT 1 FROM " +
            "telemetry_record f JOIN scan_record o ON o.recordId = f.id JOIN ScanResult s ON s.id = o.scanId " +
            "WHERE f.bodyHash = b.hash AND ${CompleteScan.SQL}) GROUP BY b.encoding ORDER BY b.encoding"
    )
    suspend fun storageObserved(): List<BodyStatsRow>

    /** Distinct bodies held only by pinned orphan facts (not counted by [storageObserved]). */
    @Query(
        "SELECT -1 AS encoding, COUNT(*) AS bodies, COALESCE(SUM(LENGTH(b.body)), 0) AS storedBytes, " +
            "COALESCE(SUM(b.rawBytes), 0) AS rawBytes FROM record_body b WHERE EXISTS (SELECT 1 FROM " +
            "telemetry_record f WHERE f.bodyHash = b.hash AND ${VisibleFact.PINNED_ORPHAN}) AND NOT EXISTS " +
            "(SELECT 1 FROM telemetry_record f2 JOIN scan_record o ON o.recordId = f2.id " +
            "JOIN ScanResult s ON s.id = o.scanId WHERE f2.bodyHash = b.hash AND ${CompleteScan.SQL})"
    )
    suspend fun storageOrphans(): BodyStatsRow
}

// Column lists shared by [TelemetryReadDao] queries (aliases: o observation, s scan, f fact, b body).
internal const val FACT_BODY_COLS = "f.eventTime AS eventTime, f.timePrecision AS timePrecision, " +
    "f.category AS category, f.subjectKey AS subjectKey, b.encoding AS encoding, " +
    "b.dictVersion AS dictVersion, b.body AS body, b.rawBytes AS rawBytes"
internal const val OBS_COLS = "f.id AS factId, o.scanId AS scanId, f.service AS service, " +
    "o.ordinal AS ordinal, o.source AS source, o.capturedAt AS capturedAt, " +
    "o.strippedKeys AS strippedKeys, $FACT_BODY_COLS"
internal const val ORPHAN_COLS = "f.id AS factId, -1 AS scanId, f.service AS service, -1 AS ordinal, " +
    "f.firstSource AS source, f.firstCapturedAt AS capturedAt, f.firstStrippedKeys AS strippedKeys, " +
    "$FACT_BODY_COLS"

/** Observations joined to their scan (s), fact (f) and body (b). */
internal const val OBS_FROM = "FROM scan_record o JOIN ScanResult s ON s.id = o.scanId " +
    "JOIN telemetry_record f ON f.id = o.recordId JOIN record_body b ON b.hash = f.bodyHash"
