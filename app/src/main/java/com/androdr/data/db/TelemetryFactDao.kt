package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.TelemetryFact

/** A fact id with the key it was looked up by (`factKey` or `sourceKey`). Plain: holds a `ByteArray`. */
class FactIdRow(val key: ByteArray, val id: Long)

/**
 * The fact pin test (spec §5.1 Pins): a fact is pinned while a `forensic_timeline` row or a
 * `signal_member` fact ref points at it. One fragment shared by every reader and by
 * [TelemetryFactDao.deleteUnobservedUnpinned]; Task D2 extends it to `scan_finding` and `alert`.
 * It refers to the fact as `telemetry_record.id`, so callers must not alias the table.
 */
object PinnedFact {
    const val SQL = "(EXISTS (SELECT 1 FROM forensic_timeline p WHERE p.recordId = telemetry_record.id) " +
        "OR EXISTS (SELECT 1 FROM signal_member m WHERE m.kind = 1 AND m.refId = telemetry_record.id))"

    /** True when no observation (of any scan) refers to the fact. */
    const val UNOBSERVED = "NOT EXISTS (SELECT 1 FROM scan_record o WHERE o.recordId = telemetry_record.id)"
}

/** Facts (`telemetry_record`). List-parameter queries must be called through [chunkedIn]/[chunkedEach]. */
@Dao
interface TelemetryFactDao {

    /** Returns each row's id, or -1 when `(service, factKey)` already exists. */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIgnore(facts: List<TelemetryFact>): List<Long>

    @Query("SELECT factKey AS `key`, id FROM telemetry_record WHERE service = :service AND factKey IN (:factKeys)")
    suspend fun idsFor(service: String, factKeys: List<ByteArray>): List<FactIdRow>

    /** Of [ids], the facts already observed by a live scan that is COMPLETE. */
    @Query(
        "SELECT DISTINCT o.recordId FROM scan_record o JOIN ScanResult s ON s.id = o.scanId " +
            "WHERE o.recordId IN (:ids) AND o.source = 'LIVE_SCAN' AND s.state = 'COMPLETE'"
    )
    suspend fun liveObserved(ids: List<Long>): List<Long>

    @Query(
        "DELETE FROM telemetry_record WHERE id IN (:ids) AND ${PinnedFact.UNOBSERVED} AND NOT ${PinnedFact.SQL}"
    )
    suspend fun deleteUnobservedUnpinned(ids: List<Long>)

    /** Keyset over fact ids for `gcUnobservedUnpinned`. */
    @Query(
        "SELECT id FROM telemetry_record WHERE id > :afterId AND ${PinnedFact.UNOBSERVED} " +
            "AND NOT ${PinnedFact.SQL} ORDER BY id LIMIT :size"
    )
    suspend fun unobservedUnpinnedAfter(afterId: Long, size: Int): List<Long>

    @Query("SELECT DISTINCT bodyHash FROM telemetry_record WHERE id IN (:ids)")
    suspend fun bodyHashesOf(ids: List<Long>): List<ByteArray>

    @Query("SELECT sourceKey AS `key`, id FROM telemetry_record WHERE sourceKey IN (:keys)")
    suspend fun idsBySourceKey(keys: List<ByteArray>): List<FactIdRow>
}
