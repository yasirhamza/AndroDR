package com.androdr.data.store

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.BodyStatsRow
import com.androdr.data.db.ScanTotals
import com.androdr.data.db.ServiceSummary
import com.androdr.data.db.StorageKind
import com.androdr.data.db.StoredRecordRow
import com.androdr.data.db.TelemetryReadDao
import com.androdr.data.db.chunkedIn
import com.androdr.data.model.TelemetrySource
import com.androdr.reporting.StoredTelemetrySource
import com.androdr.sigma.TimePrecision
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import java.io.Writer
import javax.inject.Inject
import javax.inject.Singleton

/**
 * One stored record, decoded. [fields] is null when the body is unreadable (spec §5.1: corrupt
 * or over-long bodies become a placeholder). A pinned orphan (its observations were removed by
 * deletion or retention) has [scanId] and [ordinal] [ORPHAN]; its [source] and [capturedAt]
 * are the fact's first observation's (`firstSource`/`firstCapturedAt`), and its [fields] are
 * restored with that observation's stripped keys, so provenance stays exact. [subjectKey] is the
 * fact's stored subject key ([TelemetryStore.subjectKeyOf]), kept even when the body is unreadable.
 */
data class DecodedRecord(
    val factId: Long, val scanId: Long, val service: String, val ordinal: Int, val source: TelemetrySource,
    val capturedAt: Long, val eventTime: Long?, val precision: TimePrecision, val category: String?,
    val fields: Map<String, Any?>?, val summary: String?, val subjectKey: String? = null,
) {
    companion object {
        const val ORPHAN = -1
    }
}

/** A subject that differs between two scans: [before] only, [after] only, or both (changed). */
data class RecordChange(val subjectKey: String, val before: DecodedRecord?, val after: DecodedRecord?)

/** Distinct bodies and their sizes. */
data class BodyStats(val bodies: Long, val storedBytes: Long, val rawBytes: Long) {
    operator fun plus(o: BodyStats) = BodyStats(bodies + o.bodies, storedBytes + o.storedBytes, rawBytes + o.rawBytes)

    companion object {
        val NONE = BodyStats(0, 0, 0)
    }
}

/**
 * Store size (spec §8.2): distinct bodies of facts observed by COMPLETE scans, partitioned as retention
 * keeps them ([StorageKind]): live scans' [snapshots], live scans' [liveEvents], and [imports]; a body
 * shared across kinds counts once, in the first of those (ruling R42), so they add up to [total]. Plus
 * bodies held only by pinned orphans and the bytes of alert evidence JSON.
 */
/**
 * A telemetry export that ended short: [service] of [scanId] yielded [written] of the [expected] records
 * it held when the export started (the scan was deleted or retention ran in between). The partial file is
 * discarded and the export reported as failed, never shared as if whole.
 */
class IncompleteExportException(scanId: Long, service: String, written: Long, expected: Int) :
    java.io.IOException("telemetry export of scan $scanId cut short: $service gave $written of $expected records")

data class StorageSummary(
    val snapshots: BodyStats, val liveEvents: BodyStats, val imports: BodyStats, val pinnedOrphans: BodyStats,
    val alertEvidenceBytes: Long,
) {
    /** The distinct bodies of facts observed by COMPLETE scans: the three kinds together. */
    val total: BodyStats get() = snapshots + liveEvents + imports

    companion object {
        val EMPTY = StorageSummary(BodyStats.NONE, BodyStats.NONE, BodyStats.NONE, BodyStats.NONE, 0L)
    }
}

/** Turns [StoredRecordRow]s into [DecodedRecord]s. */
internal class RecordDecoder(private val codec: TelemetryRecordCodec, private val display: EventDisplay) {
    fun decode(row: StoredRecordRow): DecodedRecord {
        val fields = codec.decode(row.body, row.encoding, row.dictVersion, row.rawBytes, row.strippedKeys, row.source,
            row.capturedAt)
        val precision = TimePrecision.entries.firstOrNull { it.name == row.timePrecision } ?: TimePrecision.EXACT
        return DecodedRecord(
            factId = row.factId, scanId = row.scanId, service = row.service, ordinal = row.ordinal,
            source = row.source, capturedAt = row.capturedAt, eventTime = row.eventTime, precision = precision,
            category = row.category, fields = fields, summary = fields?.let { display.summary(row.service, it) },
            subjectKey = row.subjectKey,
        )
    }
}

/**
 * Keyset paging over one scan's records of one service, keyed by ordinal. A non-blank [search]
 * narrows it to records whose package name or subject key contains that text (ASCII
 * case-insensitive, as SQLite's LIKE is), still keyset on ordinal.
 */
internal class ScanRecordPagingSource(
    db: AppDatabase,
    private val scanId: Long,
    private val service: String,
    private val decoder: RecordDecoder,
    search: String? = null,
) : KeysetPagingSource<Int, DecodedRecord>(db, KeysetPagingSource.OBSERVED_TABLES) {
    private val dao: TelemetryReadDao = db.telemetryReadDao()
    private val pattern: String? = search?.trim()?.takeIf { it.isNotEmpty() }?.let { "%${likeEscape(it)}%" }

    override fun keyOf(item: DecodedRecord): Int = item.ordinal

    override suspend fun loadFrom(from: Int?, size: Int) = after((from ?: Int.MIN_VALUE + 1) - 1, size)

    override suspend fun loadAfter(after: Int, size: Int) = after(after, size)

    override suspend fun loadBefore(before: Int, size: Int) = slice(
        (pattern?.let { dao.searchBefore(scanId, service, it, before, size) }
            ?: dao.pageBefore(scanId, service, before, size)).map(decoder::decode)
    )

    private suspend fun after(after: Int, size: Int) = slice(
        (pattern?.let { dao.searchAfter(scanId, service, it, after, size) }
            ?: dao.pageAfter(scanId, service, after, size)).map(decoder::decode)
    )

    companion object {
        /** Escapes LIKE's wildcards (`%`, `_`) and its escape character, so a search matches literally. */
        internal fun likeEscape(text: String): String =
            text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    }
}

/**
 * Per-scan and cross-scan reads of the telemetry store (spec §5.1). Every read shows only what
 * the visibility rule allows: records of `COMPLETE` scans, plus pinned facts with no observation
 * left. Correlation-atom reads live in `AtomReader` (Phase C); the JSONL export is [exportJsonl].
 */
@Singleton
@Suppress("TooManyFunctions") // the store's one read facade: one method per read its consumers need (spec §5.1)
class TelemetryReader @Inject constructor(
    private val db: AppDatabase,
    codec: TelemetryRecordCodec,
    display: EventDisplay,
) : StoredTelemetrySource {
    private val dao: TelemetryReadDao get() = db.telemetryReadDao()
    private val decoder = RecordDecoder(codec, display)

    override suspend fun services(scanId: Long): List<ServiceSummary> = dao.services(scanId)

    override suspend fun latestEventTime(scanId: Long, notAfter: Long): Long? =
        dao.scanTotals(scanId, notAfter).latestEventTime

    /** One scan's record count, decoded body bytes and latest exact event time (the export estimate). */
    suspend fun scanTotals(scanId: Long): ScanTotals = dao.scanTotals(scanId)

    /** One scan's records of [service], keyset-paged; a non-blank [search] narrows them ([ScanRecordPagingSource]). */
    fun page(scanId: Long, service: String, search: String? = null): Flow<PagingData<DecodedRecord>> =
        Pager(PagingConfig(pageSize = PAGE_SIZE, enablePlaceholders = false)) {
            pagingSource(scanId, service, search)
        }.flow

    internal fun pagingSource(scanId: Long, service: String, search: String? = null) =
        ScanRecordPagingSource(db, scanId, service, decoder, search)

    /** Streams one scan's records of [service] in ordinal order, [BATCH] at a time. */
    override suspend fun forEach(scanId: Long, service: String, block: suspend (DecodedRecord) -> Unit) {
        var after = Int.MIN_VALUE
        while (true) {
            val rows = dao.pageAfter(scanId, service, after, BATCH)
            for (row in rows) block(decoder.decode(row))
            if (rows.size < BATCH) return
            after = rows.last().ordinal
        }
    }

    /**
     * Every visible snapshot record (no event time) of one subject ([TelemetryStore.subjectKeyOf])
     * across scans, with its pinned orphans, in capture order; re-emitted when scans or pins change.
     * What the browser shows for a snapshot record, bounded by snapshot retention rather than an
     * event time window (spec §8.1).
     */
    fun snapshotHistory(service: String, subjectKey: String): Flow<List<DecodedRecord>> =
        db.tableChanges(HISTORY_TABLES)
            .map { dao.snapshotHistory(service, subjectKey).map(decoder::decode) }
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

    /**
     * Up to [size] facts of [service] stamped at or after [since] that a COMPLETE live scan observed,
     * with fact id > [afterId], ascending by id (the late-IOC re-check's keyset page, spec §5.2).
     */
    suspend fun liveFactsSince(service: String, since: Long, afterId: Long, size: Int): List<DecodedRecord> =
        dao.liveFactsSince(service, since, afterId, size).map(decoder::decode)

    /** The visible facts among [factIds] (batched; missing or invisible ids are omitted). */
    suspend fun records(factIds: List<Long>): List<DecodedRecord> =
        chunkedIn(factIds) { dao.records(it) }.map(decoder::decode)

    /**
     * The visible facts among [factIds] as COMPLETE scan [scanId] observed them; a fact that scan did
     * not observe (a late-IOC re-check's fact, or a pinned orphan) reads as [records] does.
     */
    suspend fun recordsInScan(scanId: Long, factIds: List<Long>): List<DecodedRecord> {
        val ids = factIds.distinct()
        val own = chunkedIn(ids) { dao.inScan(scanId, it) }.map(decoder::decode)
        val seen = own.mapTo(HashSet()) { it.factId }
        return own + records(ids.filter { it !in seen })
    }

    /**
     * Streams COMPLETE scan [scanId]'s own observations to [out] as JSONL (spec §7), one
     * [TelemetryJsonl] envelope per observation, service by service in ordinal order, read [BATCH] at a
     * time through [forEach]: no whole-scan list is held, and each line is written as soon as it is
     * decoded. An unreadable body still gets its line. Returns the number of lines written.
     *
     * The pages are separate reads, so a delete of the scan (or a retention run) between them would end
     * a service early. A COMPLETE scan's records never grow, so a service yielding fewer lines than it
     * held at the start throws [IncompleteExportException] rather than passing as a whole export (#418).
     */
    suspend fun exportJsonl(scanId: Long, out: Writer): Long {
        var lines = 0L
        for (service in services(scanId)) {
            var written = 0L
            forEach(scanId, service.service) { record ->
                out.write(TelemetryJsonl.line(record))
                out.write("\n")
                written++
            }
            if (written < service.records) throw IncompleteExportException(scanId, service.service, written, service.records)
            lines += written
        }
        return lines
    }

    suspend fun storage(): StorageSummary {
        val observed = dao.storageObserved().associateBy { it.kind }
        fun stats(row: BodyStatsRow?) = row?.let { BodyStats(it.bodies, it.storedBytes, it.rawBytes) } ?: BodyStats.NONE
        return StorageSummary(
            snapshots = stats(observed[StorageKind.SNAPSHOT]),
            liveEvents = stats(observed[StorageKind.LIVE_EVENT]),
            imports = stats(observed[StorageKind.IMPORT]),
            pinnedOrphans = stats(dao.storageOrphans()),
            alertEvidenceBytes = db.alertDao().evidenceBytes(),
        )
    }

    companion object {
        const val APP_ENRICHMENT_MAX_AGE_MS = 5L * 60_000L
        private const val PAGE_SIZE = 100
        private const val BATCH = 500

        /** Scans completing/deleting and pins changing are what change [snapshotHistory]'s result. */
        private val HISTORY_TABLES = arrayOf("ScanResult", "forensic_timeline", "signal_member")
    }
}
