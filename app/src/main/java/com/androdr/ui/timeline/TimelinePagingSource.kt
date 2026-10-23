package com.androdr.ui.timeline

import com.androdr.data.db.AppDatabase
import com.androdr.data.db.TimelineDirection
import com.androdr.data.db.TimelineFilter
import com.androdr.data.db.TimelineKey
import com.androdr.data.db.chunkedIn
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TimelineRowEntity
import com.androdr.data.store.KeysetPagingSource
import com.androdr.data.store.TelemetryReader
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The Timeline's paging source (spec §6): keyset paging over [com.androdr.data.db.TimelineDao] on
 * `(time, rowKind, seq)` — an inclusive refresh at the anchor, append after the last key, prepend
 * through the reverse-ordered query. It observes `ScanResult` and `forensic_timeline`
 * ([KeysetPagingSource.OBSERVED_TABLES]; D2 adds `alert`), never the store tables, so a scan's
 * chunk commits cause no invalidation and its data appears when it completes.
 */
class TimelinePagingSource(
    private val db: AppDatabase,
    private val filter: TimelineFilter,
    private val entries: TimelineEntries,
) : KeysetPagingSource<TimelineKey, TimelineRow.Entry>(db, KeysetPagingSource.OBSERVED_TABLES) {

    override fun keyOf(item: TimelineRow.Entry): TimelineKey = item.key

    override suspend fun loadFrom(from: TimelineKey?, size: Int) =
        entries.page(filter, from, TimelineDirection.FROM, size)

    override suspend fun loadAfter(after: TimelineKey, size: Int) =
        entries.page(filter, after, TimelineDirection.AFTER, size)

    override suspend fun loadBefore(before: TimelineKey, size: Int) =
        entries.page(filter, before, TimelineDirection.BEFORE, size)
}

/**
 * Reads Timeline pages and turns them into rows: a `forensic_timeline` row read in full (visible
 * rows only) with its nested evidence fact decoded, a fact decoded through [TelemetryReader].
 *
 * No read takes a transaction (a Room transaction holds the writer lock, which would stall an
 * import's chunk commits and the DNS monitor's inserts). The keyset page is one statement, so the
 * merge of its two arms is consistent; hydration follows in separate reads, and an entry deleted in
 * between is skipped while the page keys still come from what the keyset read ([KeysetPagingSource.Slice]).
 */
@Singleton
class TimelineEntries @Inject constructor(
    private val db: AppDatabase,
    private val reader: TelemetryReader,
) {
    suspend fun page(
        filter: TimelineFilter, key: TimelineKey?, direction: TimelineDirection, size: Int,
    ): KeysetPagingSource.Slice<TimelineKey, TimelineRow.Entry> {
        val entities = db.timelineDao().page(filter, key, direction, size)
        return KeysetPagingSource.Slice(hydrate(entities), entities.map { it.key })
    }

    /**
     * Where fact [factId] came from (I4): the source that created it and the distinct sources of its
     * visible observations — what the source filter matches. Null when the fact is not visible.
     */
    suspend fun provenance(factId: Long): FactProvenance? {
        val dao = db.telemetryReadDao()
        val first = dao.firstSource(factId) ?: return null
        return FactProvenance(first, dao.observedSources(factId))
    }

    /** What the list shows for [filter] ([com.androdr.data.db.TimelineDao.count]). */
    suspend fun count(filter: TimelineFilter): Long = db.timelineDao().count(filter)

    /**
     * Streams every entry [filter] matches, [size] at a time: newest first, or oldest first when
     * [oldestFirst]. Only one page is held at a time (the export path; spec §7).
     */
    suspend fun forEachPage(
        filter: TimelineFilter, oldestFirst: Boolean, size: Int, block: suspend (List<TimelineRow.Entry>) -> Unit,
    ) {
        val direction = if (oldestFirst) TimelineDirection.BEFORE else TimelineDirection.AFTER
        var key: TimelineKey? = null
        var first = true
        while (true) {
            val page = page(filter, key, if (first && !oldestFirst) TimelineDirection.FROM else direction, size)
            first = false
            if (page.items.isNotEmpty()) block(page.items)
            if (page.keys.size < size) return
            key = page.keys.last()
        }
    }

    private suspend fun hydrate(entities: List<TimelineRowEntity>): List<TimelineRow.Entry> {
        val rowIds = entities.filter { it.rowKind == TimelineRowEntity.ROW }.map { it.id }
        val factIds = entities
            .mapNotNull { if (it.rowKind == TimelineRowEntity.FACT) it.id else it.recordId }
            .distinct()
        val rows = chunkedIn(rowIds) { db.forensicTimelineEventDao().visibleByIds(it) }.associateBy { it.id }
        val facts = chunkedIn(factIds) { reader.records(it) }.associateBy { it.factId }
        return entities.mapNotNull { e ->
            if (e.rowKind == TimelineRowEntity.ROW) {
                rows[e.id]?.let { TimelineRow.StoredRow(e, it, e.recordId?.let(facts::get)) }
            } else {
                facts[e.id]?.let { TimelineRow.EventRow(e, it) }
            }
        }
    }
}

/**
 * A fact's provenance for its detail sheet: [firstCapturedBy] created it (`firstSource`);
 * [observedBy] lists the sources of its visible observations (empty for a pinned orphan). The
 * Timeline's source filter matches [observedBy] (a pinned orphan by [firstCapturedBy]).
 */
data class FactProvenance(val firstCapturedBy: TelemetrySource, val observedBy: List<TelemetrySource>)
