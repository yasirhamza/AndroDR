package com.androdr.data.store

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.BodyStatsRow
import com.androdr.data.db.ServiceSummary
import com.androdr.data.db.StoredRecordRow
import com.androdr.data.db.TelemetryReadDao
import com.androdr.data.db.chunkedIn
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.TimePrecision
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/**
 * One stored record, decoded. [fields] is null when the body is unreadable (spec §5.1: corrupt
 * or over-long bodies become a placeholder). A pinned orphan (its observations were removed by
 * deletion or retention) has [scanId] and [ordinal] [ORPHAN]; its observation-only envelope
 * (`source`/`captured_at` when they were stripped) is gone, so [source] falls back to the
 * body's own `source` field, else [TelemetrySource.LIVE_SCAN], and [capturedAt] is 0.
 */
data class DecodedRecord(
    val factId: Long, val scanId: Long, val service: String, val ordinal: Int, val source: TelemetrySource,
    val capturedAt: Long, val eventTime: Long?, val precision: TimePrecision, val category: String?,
    val fields: Map<String, Any?>?, val summary: String?,
) {
    companion object {
        const val ORPHAN = -1
    }
}

/** A subject that differs between two scans: [before] only, [after] only, or both (changed). */
data class RecordChange(val subjectKey: String, val before: DecodedRecord?, val after: DecodedRecord?)

/** Distinct bodies and their sizes. */
data class BodyStats(val bodies: Long, val storedBytes: Long, val rawBytes: Long) {
    companion object {
        val NONE = BodyStats(0, 0, 0)
    }
}

/**
 * Store size: distinct bodies of facts observed by COMPLETE scans, by kind (snapshot bodies are
 * plain JSON, event bodies Deflate), plus bodies held only by pinned orphans and (from Task D2)
 * the bytes of alert evidence JSON.
 */
data class StorageSummary(
    val snapshots: BodyStats, val events: BodyStats, val pinnedOrphans: BodyStats, val alertEvidenceBytes: Long,
) {
    companion object {
        val EMPTY = StorageSummary(BodyStats.NONE, BodyStats.NONE, BodyStats.NONE, 0L)
    }
}

/** Turns [StoredRecordRow]s into [DecodedRecord]s. */
internal class RecordDecoder(private val codec: TelemetryRecordCodec, private val display: EventDisplay) {
    fun decode(row: StoredRecordRow): DecodedRecord {
        val source = row.source ?: TelemetrySource.LIVE_SCAN
        val fields = codec.decode(row.body, row.encoding, row.dictVersion, row.rawBytes, row.strippedKeys, source,
            row.capturedAt)
        val effectiveSource = row.source
            ?: (fields?.get("source") as? String)?.let { s -> TelemetrySource.entries.firstOrNull { it.name == s } }
            ?: TelemetrySource.LIVE_SCAN
        val precision = TimePrecision.entries.firstOrNull { it.name == row.timePrecision } ?: TimePrecision.EXACT
        return DecodedRecord(
            factId = row.factId, scanId = row.scanId, service = row.service, ordinal = row.ordinal,
            source = effectiveSource, capturedAt = row.capturedAt, eventTime = row.eventTime, precision = precision,
            category = row.category, fields = fields, summary = fields?.let { display.summary(row.service, it) },
        )
    }
}

/** Keyset paging over one scan's records of one service, keyed by ordinal. */
internal class ScanRecordPagingSource(
    db: AppDatabase,
    private val scanId: Long,
    private val service: String,
    private val decoder: RecordDecoder,
) : KeysetPagingSource<Int, DecodedRecord>(db, KeysetPagingSource.OBSERVED_TABLES) {
    private val dao: TelemetryReadDao = db.telemetryReadDao()

    override fun keyOf(item: DecodedRecord): Int = item.ordinal

    override suspend fun loadFrom(from: Int?, size: Int): List<DecodedRecord> =
        dao.pageAfter(scanId, service, (from ?: Int.MIN_VALUE + 1) - 1, size).map(decoder::decode)

    override suspend fun loadAfter(after: Int, size: Int): List<DecodedRecord> =
        dao.pageAfter(scanId, service, after, size).map(decoder::decode)

    override suspend fun loadBefore(before: Int, size: Int): List<DecodedRecord> =
        dao.pageBefore(scanId, service, before, size).map(decoder::decode)
}

/**
 * Per-scan and cross-scan reads of the telemetry store (spec §5.1). Every read shows only what
 * the visibility rule allows: records of `COMPLETE` scans, plus pinned facts with no observation
 * left. Correlation-atom reads live in `AtomReader` (Phase C), JSONL export in
 * `TelemetryExport` (Phase E).
 */
@Singleton
class TelemetryReader @Inject constructor(
    private val db: AppDatabase,
    codec: TelemetryRecordCodec,
    display: EventDisplay,
) {
    private val dao: TelemetryReadDao get() = db.telemetryReadDao()
    private val decoder = RecordDecoder(codec, display)

    suspend fun services(scanId: Long): List<ServiceSummary> = dao.services(scanId)

    fun page(scanId: Long, service: String): Flow<PagingData<DecodedRecord>> =
        Pager(PagingConfig(pageSize = PAGE_SIZE, enablePlaceholders = false)) { pagingSource(scanId, service) }.flow

    internal fun pagingSource(scanId: Long, service: String) = ScanRecordPagingSource(db, scanId, service, decoder)

    /** Streams one scan's records of [service] in ordinal order, [BATCH] at a time. */
    suspend fun forEach(scanId: Long, service: String, block: suspend (DecodedRecord) -> Unit) {
        var after = Int.MIN_VALUE
        while (true) {
            val rows = dao.pageAfter(scanId, service, after, BATCH)
            for (row in rows) block(decoder.decode(row))
            if (rows.size < BATCH) return
            after = rows.last().ordinal
        }
    }

    /**
     * Every visible record of one subject ([TelemetryStore.subjectKeyOf]) across scans, in
     * capture order, then its pinned orphans; re-emitted when scans or pins change.
     */
    fun history(service: String, subjectKey: String): Flow<List<DecodedRecord>> =
        db.tableChanges(HISTORY_TABLES)
            .map { dao.history(service, subjectKey).map(decoder::decode) }
            .flowOn(Dispatchers.IO)

    /**
     * Subjects of [service] whose record differs between [scanA] and [scanB] (both COMPLETE),
     * ordered by subject key. Records without a subject key (pure events) are not compared.
     */
    suspend fun changedBetween(scanA: Long, scanB: Long, service: String): List<RecordChange> {
        val before = HashMap<String, ArrayDeque<DecodedRecord>>()
        eachOnlyIn(scanA, scanB, service) { key, r -> before.getOrPut(key) { ArrayDeque() }.addLast(r) }
        val out = ArrayList<RecordChange>()
        eachOnlyIn(scanB, scanA, service) { key, r -> out += RecordChange(key, before[key]?.removeFirstOrNull(), r) }
        before.forEach { (key, left) -> left.forEach { out += RecordChange(key, it, null) } }
        out.sortBy { it.subjectKey }
        return out
    }

    private suspend fun eachOnlyIn(
        scanId: Long, other: Long, service: String, block: (String, DecodedRecord) -> Unit,
    ) {
        var after = Int.MIN_VALUE
        while (true) {
            val rows = dao.onlyIn(scanId, other, service, after, BATCH)
            for (row in rows) row.subjectKey?.let { block(it, decoder.decode(row)) }
            if (rows.size < BATCH) return
            after = rows.last().ordinal
        }
    }

    /**
     * The records of [service] from the newest COMPLETE live scan, if that scan captured them
     * within [maxAgeMs]; null otherwise.
     */
    suspend fun latestLive(service: String, maxAgeMs: Long): List<DecodedRecord>? {
        val scanId = dao.latestLiveScan(service, System.currentTimeMillis() - maxAgeMs) ?: return null
        val out = ArrayList<DecodedRecord>()
        forEach(scanId, service) { out += it }
        return out
    }

    /** The visible facts among [factIds] (batched; missing or invisible ids are omitted). */
    suspend fun records(factIds: List<Long>): List<DecodedRecord> =
        chunkedIn(factIds) { dao.records(it) }.map(decoder::decode)

    suspend fun storage(): StorageSummary {
        val observed = dao.storageObserved().associateBy { it.encoding }
        fun stats(row: BodyStatsRow?) = row?.let { BodyStats(it.bodies, it.storedBytes, it.rawBytes) } ?: BodyStats.NONE
        return StorageSummary(
            snapshots = stats(observed[TelemetryRecordCodec.ENCODING_PLAIN]),
            events = stats(observed[TelemetryRecordCodec.ENCODING_DEFLATE]),
            pinnedOrphans = stats(dao.storageOrphans()),
            alertEvidenceBytes = 0L,
        )
    }

    companion object {
        const val APP_ENRICHMENT_MAX_AGE_MS = 5L * 60_000L
        private const val PAGE_SIZE = 100
        private const val BATCH = 500

        /** Scans completing/deleting and pins changing are what change [history]'s result. */
        private val HISTORY_TABLES = arrayOf("ScanResult", "forensic_timeline", "signal_member")
    }
}
