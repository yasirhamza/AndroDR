package com.androdr.scanner

import android.database.sqlite.SQLiteFullException
import android.util.Log
import androidx.collection.MutableLongSet
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanWithFindings
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.data.repo.AlertIdentity
import com.androdr.data.repo.FindingCounter
import com.androdr.data.repo.FindingsRepository
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.util.zip.Deflater
import javax.inject.Inject

/**
 * What a finished session wrote.
 *
 * @property scan the completed scan (its summary columns; the findings are `scan_finding` rows), or —
 *   when [persisted] is false (the finishing write failed on a full disk) — the in-memory summary.
 * @property findings the findings the session holds in memory: every recorded finding of a live
 *   scan (bounded by rules × live records); for an import, only the display sample of findings
 *   that could not be saved ([unsaved]). An import's stored findings are read from `scan_finding`
 *   (`FindingsRepository`), never held.
 * @property spaceToFree bytes to free so the 150 MB import reserve holds again; > 0 when an import
 *   fell back to evaluate-only on the reserve, or when findings could not be saved.
 */
data class WriteResult(
    val newFacts: Int,
    val alreadyStored: Int,
    val duplicatesDropped: Int,
    val telemetryState: TelemetryState,
    val scan: ScanResult,
    val persisted: Boolean = true,
    val spaceToFree: Long = 0L,
    /** [duplicatesDropped] by service (an intrusion-log card nets them out of each type's count). */
    val duplicatesByService: Map<String, Int> = emptyMap(),
    val findings: List<Finding> = emptyList(),
    /** Findings that could not be saved even as no-fact rows (ruling R38): exact counts and a display sample. */
    val unsaved: UnsavedSummary = UnsavedSummary.NONE,
)

/**
 * The only way a writer evaluates and stores telemetry (spec §5.2 Session). A session's scan is
 * `IN_PROGRESS` (hidden) from [begin] until [Session.finish] completes it in one transaction; a
 * failed writer calls [Session.abort]. Callers hold `ScanLock.withWriter` for the whole session.
 * Every finding is stored as a `scan_finding` row of its scan (spec §5.4); nothing is capped.
 */
class ChunkedScanWriter @Inject constructor(
    private val engine: SigmaRuleEngine,
    private val store: TelemetryStore,
    private val repo: ScanWriteRepository,
    private val findings: FindingsRepository,
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

    @Suppress("TooManyFunctions") // the session steps and their private helpers share its state
    inner class Session internal constructor(
        val scan: ScanResult,
        private val liveEvents: Boolean,
        private val hooks: SessionHooks,
    ) {
        private val isImport = scan.source != TelemetrySource.LIVE_SCAN
        private val nextOrdinal = HashMap<String, Int>()
        private val counters = HashMap<String, OccurrenceCounter>()
        private val counter = FindingCounter()

        /** A live scan's recorded findings (bounded by rules × live records); empty for an import. */
        private val memory = ArrayList<Finding>()

        /** Set once a no-fact findings write itself hit a full disk (ruling R38); null while all are saved. */
        private var unsaved: UnsavedFindings? = null
        private var dedup: EvaluateOnlyDedup? = null
        private var reserveBreached = false
        private var newFacts = 0
        private var alreadyStored = 0
        private var duplicatesDropped = 0
        private val duplicatesByService = HashMap<String, Int>()
        private var stored = false
        private val row = { f: Finding -> hooks.findingRow(f, scan) }

        /** True once the session stopped storing telemetry (full disk or breached import reserve). */
        val evaluateOnly: Boolean get() = dedup != null

        /**
         * Evaluates [chunk] (≤ [CHUNK_SIZE]), then persists it and its findings in one transaction.
         * Findings are kept only for ordinals newly observed by this scan, so a duplicate record
         * yields no second one. Like every session step, it runs on [Dispatchers.Default]:
         * evaluation, canonical JSON, Deflate and hashing are CPU work, and callers may be on the
         * main thread (A8 D2).
         */
        suspend fun append(service: String, source: TelemetrySource, capturedAt: Long, chunk: List<StoreRecord>) {
            require(chunk.size <= CHUNK_SIZE) { "chunk of ${chunk.size} exceeds $CHUNK_SIZE" }
            if (chunk.isEmpty()) return
            withContext(Dispatchers.Default) { appendChunk(service, source, capturedAt, chunk) }
        }

        @Suppress("TooGenericExceptionCaught") // a failed persist keeps its findings in memory, then rethrows
        private suspend fun appendChunk(
            service: String, source: TelemetrySource, capturedAt: Long, chunk: List<StoreRecord>,
        ) {
            val first = nextOrdinal.getOrDefault(service, 0)
            nextOrdinal[service] = first + chunk.size
            if (isImport && !evaluateOnly && !preflight.reserveOk()) {
                reserveBreached = true
                enterEvaluateOnly()
            }
            val found = engine.evaluateRecords(service, chunk, first)
            val result = try {
                if (evaluateOnly) null else persistOrFallBack(service, source, capturedAt, chunk, first, found)
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                // The writer aborts on this failure; [keptScan] still shows what this chunk found.
                // Deliberately over-reports: with nothing persisted there is no observed-this-scan
                // filter, so a live event an earlier scan reported, or a record repeated in the
                // chunk, can show its finding again. On an aborted, partial scan that beats
                // reading clean (review N2).
                found.forEach(::count)
                throw t
            }
            if (result != null) {
                recordTotals(service, result.chunk, result.kept)
            } else {
                val dup = checkNotNull(dedup).duplicates(service, chunk) { store.sourceFactKey(source, capturedAt, it) }
                val kept = found.filter { f -> dup.getOrNull(f.ordinal - first) != true && findings.keepsRow(f) }
                kept.forEach(::count)
                saveEvaluateOnly(kept) { findings.recordNoFact(scan.id, it, row) }
            }
        }

        /**
         * Evaluate-only findings are stored chunk by chunk as no-fact rows, each chunk in its own small
         * transaction, so nothing is held (spec §5.2, ruling R38). Once such a write itself hits a full
         * disk, the rest are only counted and sampled for display ([UnsavedFindings]).
         */
        private suspend fun saveEvaluateOnly(kept: List<Finding>, write: suspend (List<Finding>) -> Unit) {
            if (kept.isEmpty()) return
            val pending = unsaved
            if (pending != null) return pending.addAll(kept)
            try {
                repo.inTransaction { write(kept) }
            } catch (_: SQLiteFullException) {
                unsaved = UnsavedFindings().also { it.addAll(kept) }
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
         * `recordId = factId` and `ordinal = -1`, and is kept only when no alert with its record key
         * exists (spec §5.2): alerts are permanent, so a fact that already fired never re-fires, even
         * after the scan that first found it is deleted.
         */
        suspend fun evaluateStored(service: String, facts: Sequence<Pair<Long, StoreRecord>>) =
            withContext(Dispatchers.Default) { evaluateStoredChunks(service, facts) }

        private suspend fun evaluateStoredChunks(service: String, facts: Sequence<Pair<Long, StoreRecord>>) {
            facts.constrainOnce().chunked(CHUNK_SIZE).forEach { batch ->
                val found = engine.evaluateRecords(service, batch.map { it.second }, 0)
                    .filter { it.triggered }
                    .map { it.copy(recordId = batch[it.ordinal].first, ordinal = -1) }
                if (found.isEmpty()) return@forEach
                val keys = found.map { AlertIdentity.recordKey(it.ruleId, checkNotNull(it.recordId), it.evidence) }
                val fired = findings.existingAlertKeys(keys)
                val fresh = found.filterIndexed { i, _ -> HashKeys.key(keys[i]) !in fired }
                if (fresh.isEmpty()) return@forEach
                fresh.forEach(::count)
                if (evaluateOnly) {
                    saveEvaluateOnly(fresh) { findings.recordStored(scan.id, it, row) }
                } else {
                    repo.inTransaction { findings.recordStored(scan.id, fresh, row) }
                }
            }
        }

        /**
         * Opens the single finishing transaction. On a full disk the in-memory result is returned
         * (`persisted = false`), the storage-health flag is set and the scan is cleaned up.
         */
        suspend fun finish(): WriteResult = withContext(Dispatchers.Default) { finishOnWorker() }

        private suspend fun finishOnWorker(): WriteResult {
            if (isImport && !evaluateOnly && !preflight.reserveOk()) {
                reserveBreached = true
                enterEvaluateOnly()
            }
            val state = when {
                evaluateOnly -> TelemetryState.FAILED
                stored -> TelemetryState.STORED
                else -> TelemetryState.NONE
            }
            val spaceToFree = if (reserveBreached || unsaved != null) preflight.shortfall() else 0L
            // Nothing is buffered: every finding that could be stored already is, so a failed finish
            // never loses stored findings to a buffered write (ruling R38).
            val startNs = System.nanoTime()
            val finished = try {
                repo.finish(scan, counter.totals(), hooks, state)
            } catch (e: SQLiteFullException) {
                return inMemoryResult(spaceToFree, e)
            }
            // Spec §5.2 budget: finish ≤ 2 s on a typical 100k-finding import (verified on device).
            Log.i(TAG, "finish scan ${scan.id}: ${(System.nanoTime() - startNs) / NANOS_PER_MS} ms")
            val held = if (isImport) heldFindings() else heldFindings() + finished.correlationFindings
            return WriteResult(newFacts, alreadyStored, duplicatesDropped, state, finished.scan, true, spaceToFree,
                duplicatesByService.toMap(), held, UnsavedSummary.of(unsaved))
        }

        /**
         * The scan as this session holds it in memory: its summary and held findings, `FAILED`. A
         * writer whose session failed returns this (after [abort]) so the findings stay visible.
         */
        fun keptScan(): ScanWithFindings {
            val totals = counter.totals()
            val summary = hooks.summarize(totals.applyTo(scan), totals)
                .copy(id = scan.id, telemetryState = TelemetryState.FAILED)
            return ScanWithFindings(summary, heldFindings())
        }

        /** Unaudited cleanup delete of this session's scan; runs to completion even when cancelled. */
        suspend fun abort() = withContext(NonCancellable) { repo.cleanupDelete(scan.id) }

        /** A chunk's persist result and the findings recorded with it. */
        private inner class Persisted(val chunk: ChunkResult, val kept: List<Finding>)

        @Suppress("LongParameterList")
        private suspend fun persistOrFallBack(
            service: String, source: TelemetrySource, capturedAt: Long, chunk: List<StoreRecord>, first: Int,
            found: List<Finding>,
        ): Persisted? {
            val deflater = Deflater()
            return try {
                val counter = counters.getOrPut(service) { OccurrenceCounter() }
                // Only services that can carry events need the already-observed check (spec §5.2).
                val live = liveEvents && service in TaxonomyContract.eventServices
                repo.inTransaction {
                    val result = store.persistChunk(scan.id, service, source, capturedAt, chunk, first, counter,
                        deflater, live)
                    Persisted(result, findings.recordChunk(scan.id, first, found, result, row))
                }.also { stored = true }
            } catch (_: SQLiteFullException) {
                // The rest of the pass continues evaluate-only (spec §5.2); the counter is now invalid.
                enterEvaluateOnly()
                null
            } finally {
                deflater.end()
            }
        }

        private fun recordTotals(service: String, result: ChunkResult, kept: List<Finding>) {
            newFacts += result.newFacts
            alreadyStored += result.alreadyStored
            duplicatesDropped += result.duplicatesDropped
            if (result.duplicatesDropped > 0) duplicatesByService.merge(service, result.duplicatesDropped, Int::plus)
            kept.forEach(::count)
        }

        private fun count(f: Finding) {
            counter.offer(f)
            if (!isImport) memory += f
        }

        /** Live: every recorded finding; import: the display sample of what could not be saved. */
        private fun heldFindings(): List<Finding> = if (isImport) unsaved?.sample().orEmpty() else memory.toList()

        private fun enterEvaluateOnly() {
            if (dedup == null) dedup = EvaluateOnlyDedup()
        }

        private suspend fun inMemoryResult(spaceToFree: Long, cause: Throwable): WriteResult {
            withContext(NonCancellable) {
                health.set()
                runCatching { repo.cleanupDelete(scan.id) }.exceptionOrNull()?.let { cause.addSuppressed(it) }
            }
            val kept = keptScan()
            return WriteResult(newFacts, alreadyStored, duplicatesDropped, TelemetryState.FAILED, kept.scan, false,
                spaceToFree, duplicatesByService.toMap(), kept.findings, UnsavedSummary.of(unsaved))
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

private const val TAG = "ChunkedScanWriter"
private const val NANOS_PER_MS = 1_000_000L
