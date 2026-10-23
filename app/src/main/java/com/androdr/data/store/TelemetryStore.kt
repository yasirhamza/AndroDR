package com.androdr.data.store

import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.chunkedEach
import com.androdr.data.db.chunkedIn
import com.androdr.data.model.RecordBody
import com.androdr.data.model.ScanObservation
import com.androdr.data.model.TelemetryFact
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.StoreRecord
import com.androdr.sigma.TaxonomyContract
import com.androdr.sigma.TimelineCategories
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.util.zip.Deflater
import javax.inject.Inject
import javax.inject.Singleton

/**
 * What one [TelemetryStore.persistChunk] wrote. Arrays are indexed by `ordinal - firstOrdinal`.
 *
 * @property observed observations inserted for this scan.
 * @property newFacts distinct facts created by this chunk.
 * @property alreadyStored records whose fact existed before this chunk.
 * @property duplicatesDropped records dropped as an exact duplicate within the scan
 *   (unique `(scanId, recordId)`).
 */
@Suppress("ArrayInDataClass") // read-only result; never compared or hashed
data class ChunkResult(
    val observed: Int,
    val newFacts: Int,
    val alreadyStored: Int,
    val duplicatesDropped: Int,
    val factIdByChunkIndex: LongArray,
    val isEventByChunkIndex: BooleanArray,
    val observedThisScanByChunkIndex: BooleanArray,
)

/** One record of a chunk, ready to write. */
private class Prepared(val body: RecordBody, val fact: TelemetryFact, val isEvent: Boolean, val strippedKeys: Int)

/**
 * Writes telemetry as content ([RecordBody]), facts ([TelemetryFact]) and observations
 * ([ScanObservation]), and deletes a scan's telemetry without ever leaving an unpinned fact
 * with no observation (spec §5.1).
 *
 * Every pin-removing path passes the facts it un-pins to [releaseUnpinned] in the same
 * transaction.
 */
@Singleton
class TelemetryStore @Inject constructor(
    private val db: AppDatabase,
    private val codec: TelemetryRecordCodec,
    private val dirty: StoreDirtyFlag,
) {
    private val bodies get() = db.recordBodyDao()
    private val facts get() = db.telemetryFactDao()
    private val observations get() = db.scanObservationDao()

    /**
     * Persists [chunk] (ordinals `firstOrdinal until firstOrdinal + chunk.size`) for [scanId] in
     * one transaction: bodies → facts → observations, each `INSERT OR IGNORE`. With
     * [liveEvents], an event record whose fact already has a live observation (of a COMPLETE
     * scan) gets no new observation. The caller owns [deflater] and [counter].
     *
     * [counter] is advanced before the transaction runs, so after this throws it is no longer
     * valid for the session: a retry with the same counter would mint different fact keys for
     * id-less records. A failed chunk fails the session (spec §5.2); never retry with it.
     */
    @Suppress("LongParameterList")
    suspend fun persistChunk(
        scanId: Long, service: String, source: TelemetrySource, capturedAt: Long,
        chunk: List<StoreRecord>, firstOrdinal: Int, counter: OccurrenceCounter, deflater: Deflater,
        liveEvents: Boolean,
    ): ChunkResult {
        val prepared = chunk.map { prepare(service, source, capturedAt, it, counter, deflater) }
        return db.withTransaction {
            bodies.insertIgnore(prepared.map { it.body }.distinctBy { HashKeys.key(it.hash) })
            val (ids, isNew) = factIds(service, prepared)
            val skip = if (liveEvents) liveObservedEvents(prepared, ids, isNew) else emptySet()
            writeObservations(scanId, service, source, capturedAt, firstOrdinal, prepared, ids, isNew, skip)
        }
    }

    private fun prepare(
        service: String, source: TelemetrySource, capturedAt: Long, record: StoreRecord,
        counter: OccurrenceCounter, deflater: Deflater,
    ): Prepared {
        val fields = record.fields
        val stripped = codec.strip(fields, source, capturedAt)
        val canonical = codec.canonicalJson(stripped.fields)
        val bodyHash = HashKeys.h128(canonical)
        val eventTime = TaxonomyContract.eventTimeOf(service, fields)
        val encoded = codec.encode(service, canonical, eventTime != null, deflater)
        val key = record.sourceEventKey
        val factKey = if (key != null) {
            keyedFactKey(key, bodyHash)
        } else {
            HashKeys.h128("${hex(bodyHash)}#${counter.next(bodyHash)}")
        }
        val fact = TelemetryFact(
            service = service, factKey = factKey, sourceKey = key?.let { HashKeys.h128(it) },
            subjectKey = subjectKeyOf(service, fields), eventTime = eventTime,
            timePrecision = TaxonomyContract.precisionOf(service, fields).name,
            category = TimelineCategories.categoryOf(service, fields),
            packageName = TaxonomyContract.packageField(service)?.let { fields[it]?.toString() },
            bodyHash = bodyHash,
            firstSource = source, firstCapturedAt = capturedAt, firstStrippedKeys = stripped.strippedKeys,
        )
        val body = RecordBody(bodyHash, encoded.encoding, encoded.dictVersion, encoded.body, encoded.rawBytes)
        return Prepared(body, fact, eventTime != null, stripped.strippedKeys)
    }

    /**
     * The fact key [persistChunk] gives [record] when it has a source event key (stripped and
     * canonicalised exactly as stored), or null without one. Evaluate-only deduplication uses it.
     */
    fun sourceFactKey(source: TelemetrySource, capturedAt: Long, record: StoreRecord): ByteArray? {
        val key = record.sourceEventKey ?: return null
        val canonical = codec.canonicalJson(codec.strip(record.fields, source, capturedAt).fields)
        return keyedFactKey(key, HashKeys.h128(canonical))
    }

    /** Each record's fact id, and whether this chunk created it (first occurrence only). */
    private suspend fun factIds(service: String, prepared: List<Prepared>): Pair<LongArray, BooleanArray> {
        val inserted = facts.insertIgnore(prepared.map { it.fact })
        val ids = LongArray(prepared.size)
        val isNew = BooleanArray(prepared.size)
        val missing = ArrayList<ByteArray>()
        prepared.forEachIndexed { i, p ->
            if (inserted[i] != -1L) {
                ids[i] = inserted[i]
                isNew[i] = true
            } else {
                missing += p.fact.factKey
            }
        }
        val found = HashMap<ByteBuffer, Long>()
        val distinct = missing.distinctBy { HashKeys.key(it) }
        chunkedIn(distinct) { keys -> facts.idsFor(service, keys) }.forEach { found[HashKeys.key(it.key)] = it.id }
        prepared.forEachIndexed { i, p ->
            if (!isNew[i]) ids[i] = checkNotNull(found[HashKeys.key(p.fact.factKey)]) { "fact vanished mid-chunk" }
        }
        return ids to isNew
    }

    /** Chunk indices of event records whose pre-existing fact a COMPLETE live scan already observed. */
    private suspend fun liveObservedEvents(prepared: List<Prepared>, ids: LongArray, isNew: BooleanArray): Set<Int> {
        val candidates = prepared.indices.filter { prepared[it].isEvent && !isNew[it] }
        if (candidates.isEmpty()) return emptySet()
        val observed = chunkedIn(candidates.map { ids[it] }) { facts.liveObserved(it) }.toHashSet()
        return candidates.filterTo(HashSet()) { ids[it] in observed }
    }

    @Suppress("LongParameterList")
    private suspend fun writeObservations(
        scanId: Long, service: String, source: TelemetrySource, capturedAt: Long, firstOrdinal: Int,
        prepared: List<Prepared>, ids: LongArray, isNew: BooleanArray, skip: Set<Int>,
    ): ChunkResult {
        val written = prepared.indices.filter { it !in skip }
        val rows = observations.insertIgnore(written.map { i ->
            ScanObservation(scanId, service, firstOrdinal + i, ids[i], prepared[i].fact.eventTime, source, capturedAt,
                prepared[i].strippedKeys)
        })
        val observedNow = BooleanArray(prepared.size)
        written.forEachIndexed { k, i -> observedNow[i] = rows[k] != -1L }
        val createdHere = ids.filterIndexed { i, _ -> isNew[i] }.toHashSet()
        val alreadyStored = ids.count { it !in createdHere }
        return ChunkResult(
            observed = observedNow.count { it },
            newFacts = isNew.count { it },
            alreadyStored = alreadyStored,
            duplicatesDropped = rows.count { it == -1L },
            factIdByChunkIndex = ids,
            isEventByChunkIndex = BooleanArray(prepared.size) { prepared[it].isEvent },
            observedThisScanByChunkIndex = observedNow,
        )
    }

    /**
     * Deletes [scanId]'s observations and the telemetry only they kept alive. Idempotent. Keyset
     * batches on the observation PK, each one transaction: observations → that batch's facts with
     * no observation and no pin → bodies no fact references. On failure sets [StoreDirtyFlag].
     */
    suspend fun deleteScanTelemetry(scanId: Long) = markDirtyOnFailure {
        var more = true
        while (more) more = deleteBatch(scanId, DELETE_BATCH)
    }

    /** One delete batch of at most [size] observations; false when none were left. */
    internal suspend fun deleteBatch(scanId: Long, size: Int): Boolean = db.withTransaction {
        val batch = observations.factIdsAfter(scanId, "", Int.MIN_VALUE, size)
        if (batch.isEmpty()) return@withTransaction false
        val last = batch.last()
        observations.deleteThrough(scanId, last.service, last.ordinal)
        releaseUnpinned(batch.map { it.recordId })
        true
    }

    /**
     * Deletes those of [factIds] that have no observation and no pin, then bodies left
     * unreferenced. Call inside the transaction that removed their observations or pins.
     */
    suspend fun releaseUnpinned(factIds: Collection<Long>) {
        val ids = factIds.distinct()
        val hashes = chunkedIn(ids) { facts.bodyHashesOf(it) }.distinctBy { HashKeys.key(it) }
        chunkedEach(ids) { facts.deleteUnobservedUnpinned(it) }
        chunkedEach(hashes) { bodies.deleteUnreferenced(it) }
    }

    /**
     * Removes every fact with no observation and no pin (left by a failed delete or retention
     * batch), keyset over fact ids, one transaction per batch; clears [StoreDirtyFlag] after a
     * completed pass. Run only when the startup sweep found scans or the flag is set.
     */
    suspend fun gcUnobservedUnpinned() {
        markDirtyOnFailure {
            var after = 0L
            while (true) {
                val ids = facts.unobservedUnpinnedAfter(after, DELETE_BATCH)
                if (ids.isEmpty()) break
                db.withTransaction { releaseUnpinned(ids) }
                after = ids.last()
            }
        }
        dirty.clear()
    }

    /** Runs [block]; if it throws (cancellation included), sets [StoreDirtyFlag] and rethrows. */
    private suspend fun <T> markDirtyOnFailure(block: suspend () -> T): T = try {
        block()
    } catch (@Suppress("TooGenericExceptionCaught") e: Exception) {
        withContext(NonCancellable) { dirty.set() }
        throw e
    }

    companion object {
        private fun hex(hash: ByteArray): String = hash.joinToString("") { "%02x".format(it) }

        /** `H("src:" + sourceEventKey + "#" + bodyHash)` (spec §5.1 fact identity). */
        private fun keyedFactKey(key: String, bodyHash: ByteArray): ByteArray =
            HashKeys.h128("src:$key#${hex(bodyHash)}")

        /** Observations (or facts, for GC) per delete transaction. */
        const val DELETE_BATCH = 500

        /**
         * A record's subject: its service's key-field values joined with `|` (null when the
         * service has no key fields or every key value is absent). [TelemetryReader.history]
         * takes this key.
         */
        fun subjectKeyOf(service: String, fields: Map<String, Any?>): String? {
            val keys = TaxonomyContract.keyFields(service)
            if (keys.isEmpty() || keys.all { fields[it] == null }) return null
            return keys.joinToString("|") { fields[it]?.toString().orEmpty() }
        }
    }
}
