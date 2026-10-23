package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.TelemetryFact

/** A fact id with the key it was looked up by (`factKey` or `sourceKey`). Plain: holds a `ByteArray`. */
class FactIdRow(val key: ByteArray, val id: Long)

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

    /** Of [ids], deletes the facts with no observation and no pin (spec §5.1 Delete). */
    @Query(
        "DELETE FROM telemetry_record WHERE id IN (SELECT f.id FROM telemetry_record f WHERE f.id IN (:ids) " +
            "AND ${PinnedFact.UNOBSERVED} AND NOT ${PinnedFact.SQL})"
    )
    suspend fun deleteUnobservedUnpinned(ids: List<Long>)

    /** Keyset over fact ids for `gcUnobservedUnpinned`. */
    @Query(
        "SELECT f.id FROM telemetry_record f WHERE f.id > :afterId AND ${PinnedFact.UNOBSERVED} " +
            "AND NOT ${PinnedFact.SQL} ORDER BY f.id LIMIT :size"
    )
    suspend fun unobservedUnpinnedAfter(afterId: Long, size: Int): List<Long>

    @Query("SELECT DISTINCT bodyHash FROM telemetry_record WHERE id IN (:ids)")
    suspend fun bodyHashesOf(ids: List<Long>): List<ByteArray>

    @Query("SELECT sourceKey AS `key`, id FROM telemetry_record WHERE sourceKey IN (:keys)")
    suspend fun idsBySourceKey(keys: List<ByteArray>): List<FactIdRow>
}
