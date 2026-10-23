package com.androdr.scanner

import android.database.sqlite.SQLiteFullException
import androidx.collection.MutableLongSet
import com.androdr.data.db.RuleRecord
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.data.repo.KeptFinding
import com.androdr.data.repo.ScanWriteRepository
import com.androdr.data.repo.SessionHooks
import com.androdr.data.store.ChunkResult
import com.androdr.data.store.HashKeys
import com.androdr.data.store.OccurrenceCounter
import com.androdr.data.store.StorageHealthFlag
import com.androdr.data.store.StoragePreflight
import com.androdr.data.store.TelemetryStore
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.StoreRecord
import com.androdr.sigma.TaxonomyContract
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.util.zip.Deflater
import javax.inject.Inject

/**
 * What a finished session wrote.
 *
 * @property scan the completed scan with its kept findings — the in-memory result when [persisted]
 *   is false (the findings write itself failed on a full disk).
 * @property spaceToFree bytes to free so the 150 MB import reserve holds again; > 0 only when an
 *   import fell back to evaluate-only on the reserve.
 */
data class WriteResult(
    val newFacts: Int,
    val alreadyStored: Int,
    val duplicatesDropped: Int,
    val telemetryState: TelemetryState,
    val scan: ScanResult,
    val persisted: Boolean = true,
    val spaceToFree: Long = 0L,
)

/**
 * The only way a writer evaluates and stores telemetry (spec §5.2 Session). A session's scan is
 * `IN_PROGRESS` (hidden) from [begin] until [Session.finish] completes it in one transaction; a
 * failed writer calls [Session.abort]. Callers hold `ScanLock.withWriter` for the whole session.
 */
class ChunkedScanWriter @Inject constructor(
    private val engine: SigmaRuleEngine,
    private val store: TelemetryStore,
    private val repo: ScanWriteRepository,
    private val preflight: StoragePreflight,
    private val health: StorageHealthFlag,
) {
    /**
     * Inserts [scan] `IN_PROGRESS` and opens its session. [liveEvents]: a live event fact already
     * observed by an earlier live scan gets no new observation (and so no finding); the services
     * checked are the live event services, [TaxonomyContract.eventServices].
     */
    suspend fun begin(scan: ScanResult, liveEvents: Boolean, hooks: SessionHooks = SessionHooks.NONE): Session {
        repo.begin(scan)
        return Session(scan, liveEvents, hooks)
    }

    inner class Session internal constructor(
        val scan: ScanResult,
        private val liveEvents: Boolean,
        private val hooks: SessionHooks,
    ) {
        private val isImport = scan.source != TelemetrySource.LIVE_SCAN
        private val nextOrdinal = HashMap<String, Int>()
        private val counters = HashMap<String, OccurrenceCounter>()
        private val topK = FindingsTopK.forSource(scan.source)
        private var dedup: EvaluateOnlyDedup? = null
        private var reserveBreached = false
        private var newFacts = 0
        private var alreadyStored = 0
        private var duplicatesDropped = 0
        private var stored = false

        /** True once the session stopped storing telemetry (full disk or breached import reserve). */
        val evaluateOnly: Boolean get() = dedup != null

        /**
         * Evaluates [chunk] (≤ [CHUNK_SIZE]), then persists it in one transaction. Findings are kept
         * only for ordinals newly observed by this scan, so a duplicate record yields no second one.
         */
        @Suppress("TooGenericExceptionCaught") // a failed persist keeps its findings in memory, then rethrows
        suspend fun append(service: String, source: TelemetrySource, capturedAt: Long, chunk: List<StoreRecord>) {
            require(chunk.size <= CHUNK_SIZE) { "chunk of ${chunk.size} exceeds $CHUNK_SIZE" }
            if (chunk.isEmpty()) return
            val first = nextOrdinal.getOrDefault(service, 0)
            nextOrdinal[service] = first + chunk.size
            if (isImport && !evaluateOnly && !preflight.reserveOk()) {
                reserveBreached = true
                enterEvaluateOnly()
            }
            val findings = engine.evaluateRecords(service, chunk, first)
            val result = try {
                if (evaluateOnly) null else persistOrFallBack(service, source, capturedAt, chunk, first)
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                // The writer aborts on this failure; [keptScan] still shows what this chunk found.
                // Deliberately over-reports: with nothing persisted there is no observed-this-scan
                // filter, so a live event an earlier scan reported, or a record repeated in the
                // chunk, can show its finding again. On an aborted, partial scan that beats
                // reading clean (review N2).
                findings.forEach { topK.offer(it, null) }
                throw t
            }
            if (result != null) {
                keepObserved(findings, first, result)
                hooks.onChunk(service, source, chunk, first, result.factIdByChunkIndex,
                    result.observedThisScanByChunkIndex)
            } else {
                val dup = checkNotNull(dedup).duplicates(service, chunk) { store.sourceFactKey(source, capturedAt, it) }
                findings.forEach { f -> if (dup.getOrNull(f.ordinal - first) != true) topK.offer(f, null) }
                hooks.onChunk(service, source, chunk, first, null, null)
            }
        }

        /** [records] pulled lazily (once) and appended in chunks of [CHUNK_SIZE]. */
        suspend fun appendAll(
            service: String, source: TelemetrySource, capturedAt: Long, records: Sequence<StoreRecord>,
        ) {
            records.constrainOnce().chunked(CHUNK_SIZE).forEach { append(service, source, capturedAt, it) }
        }

        /**
         * Late-IOC re-check over stored facts: no observations are written. A finding carries
         * `recordId = factId` and `ordinal = -1`, and is kept only when no visible finding row for
         * the same `(ruleId, recordId)` exists (the Phase A–C alert-identity stand-in).
         */
        suspend fun evaluateStored(service: String, facts: Sequence<Pair<Long, StoreRecord>>) {
            facts.constrainOnce().chunked(CHUNK_SIZE).forEach { batch ->
                val findings = engine.evaluateRecords(service, batch.map { it.second }, 0)
                if (findings.isEmpty()) return@forEach
                val existing = repo.existingFindings(findings.map { batch[it.ordinal].first })
                for (f in findings) {
                    val factId = batch[f.ordinal].first
                    if (RuleRecord(f.ruleId, factId) in existing) continue
                    topK.offer(f.copy(recordId = factId, ordinal = -1), factId)
                }
            }
        }

        /**
         * Opens the single finishing transaction. On a full disk the in-memory result is returned
         * (`persisted = false`), the storage-health flag is set and the scan is cleaned up.
         */
        suspend fun finish(): WriteResult {
            if (isImport && !evaluateOnly && !preflight.reserveOk()) {
                reserveBreached = true
                enterEvaluateOnly()
            }
            val state = when {
                evaluateOnly -> TelemetryState.FAILED
                stored -> TelemetryState.STORED
                else -> TelemetryState.NONE
            }
            val kept = topK.result()
            val spaceToFree = if (reserveBreached) preflight.shortfall() else 0L
            val completed = try {
                repo.finish(scan, kept, topK.totals(), hooks, state)
            } catch (e: SQLiteFullException) {
                return inMemoryResult(kept, spaceToFree, e)
            }
            return WriteResult(newFacts, alreadyStored, duplicatesDropped, state, completed, true, spaceToFree)
        }

        /**
         * The scan as this session holds it in memory: its kept findings and summary, `FAILED`. A
         * writer whose session failed returns this (after [abort]) so the findings stay visible.
         */
        fun keptScan(): ScanResult =
            hooks.summarize(scan.copy(findings = topK.result().map { it.finding }), topK.totals())
                .copy(id = scan.id, telemetryState = TelemetryState.FAILED)

        /** Unaudited cleanup delete of this session's scan; runs to completion even when cancelled. */
        suspend fun abort() = withContext(NonCancellable) { repo.cleanupDelete(scan.id) }

        private suspend fun persistOrFallBack(
            service: String, source: TelemetrySource, capturedAt: Long, chunk: List<StoreRecord>, first: Int,
        ): ChunkResult? {
            val deflater = Deflater()
            return try {
                val counter = counters.getOrPut(service) { OccurrenceCounter() }
                // Only services that can carry events need the already-observed check (spec §5.2).
                val live = liveEvents && service in TaxonomyContract.eventServices
                store.persistChunk(scan.id, service, source, capturedAt, chunk, first, counter, deflater, live)
                    .also { stored = true }
            } catch (_: SQLiteFullException) {
                // The rest of the pass continues evaluate-only (spec §5.2); the counter is now invalid.
                enterEvaluateOnly()
                null
            } finally {
                deflater.end()
            }
        }

        private fun keepObserved(findings: List<Finding>, first: Int, result: ChunkResult) {
            newFacts += result.newFacts
            alreadyStored += result.alreadyStored
            duplicatesDropped += result.duplicatesDropped
            for (f in findings) {
                val i = f.ordinal - first
                if (i in result.observedThisScanByChunkIndex.indices && result.observedThisScanByChunkIndex[i]) {
                    topK.offer(f, result.factIdByChunkIndex[i])
                }
            }
        }

        private fun enterEvaluateOnly() {
            if (dedup == null) dedup = EvaluateOnlyDedup()
        }

        private suspend fun inMemoryResult(kept: List<KeptFinding>, spaceToFree: Long, cause: Throwable): WriteResult {
            withContext(NonCancellable) {
                health.set()
                runCatching { repo.cleanupDelete(scan.id) }.exceptionOrNull()?.let { cause.addSuppressed(it) }
            }
            val inMemory = hooks.summarize(scan.copy(findings = kept.map { it.finding }), topK.totals())
                .copy(id = scan.id, telemetryState = TelemetryState.FAILED)
            return WriteResult(newFacts, alreadyStored, duplicatesDropped, TelemetryState.FAILED, inMemory, false,
                spaceToFree)
        }
    }

    companion object {
        /** Records per append (and per transaction). */
        const val CHUNK_SIZE = 5_000
    }
}

/**
 * Evaluate-only duplicate filter (spec §9 M1): stands in for the store's unique
 * `(scanId, recordId)` once nothing is stored. Only records with a source event key can be exact
 * duplicates (id-less content repeats are distinct facts by occurrence); the key is the store's own
 * fact key ([TelemetryStore.sourceFactKey]) with the service. Remembers at most [capacity] 64-bit
 * prefixes (~3 MB at 200,000); past that, nothing more is deduplicated.
 */
internal class EvaluateOnlyDedup(private val capacity: Int = MAX_KEYS) {
    private val seen = MutableLongSet()

    /** Per chunk index: true when that record repeats one already seen in this session. */
    fun duplicates(service: String, chunk: List<StoreRecord>, factKey: (StoreRecord) -> ByteArray?): BooleanArray =
        BooleanArray(chunk.size) { i ->
            val key = factKey(chunk[i]) ?: return@BooleanArray false
            isRepeat(HashKeys.h128(service.toByteArray(Charsets.UTF_8) + key))
        }

    private fun isRepeat(hash: ByteArray): Boolean {
        val prefix = ByteBuffer.wrap(hash, 0, Long.SIZE_BYTES).long
        return when {
            prefix in seen -> true
            seen.size < capacity -> { seen += prefix; false }
            else -> false
        }
    }

    companion object {
        const val MAX_KEYS = 200_000
    }
}
