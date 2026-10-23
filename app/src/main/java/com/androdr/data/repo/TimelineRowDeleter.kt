package com.androdr.data.repo

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.store.TelemetryStore
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The only caller of `ForensicTimelineEventDao`'s row deletes. A `forensic_timeline` row with a
 * `recordId` pins that fact (spec §5.1 Pins), so each delete reads the facts its rows pin, deletes
 * the rows, and passes those facts to [TelemetryStore.releaseUnpinned] — which removes any left with
 * no observation and no other pin.
 *
 * Transaction-agnostic: every function must run inside the caller's Room transaction, so the
 * release commits (or rolls back) with the delete.
 */
@Singleton
class TimelineRowDeleter @Inject constructor(
    private val dao: ForensicTimelineEventDao,
    private val store: TelemetryStore,
) {
    /** The 30-day prune of non-persistent rows (audit/closure rows are kept). */
    suspend fun olderThan(cutoff: Long) {
        val pinned = dao.recordIdsOlderThan(cutoff)
        dao.deleteOlderThan(cutoff)
        store.releaseUnpinned(pinned)
    }

    suspend fun bySource(source: String) {
        val pinned = dao.recordIdsBySource(source)
        dao.deleteBySource(source)
        store.releaseUnpinned(pinned)
    }

    /** A scan's own non-persistent rows. */
    suspend fun byScanId(scanId: Long) {
        val pinned = dao.recordIdsByScanId(scanId)
        dao.deleteByScanId(scanId)
        store.releaseUnpinned(pinned)
    }

    /** "Clear all": non-persistent rows that are scan-less or whose scan no longer exists. */
    suspend fun unownedNonPersistent() {
        val pinned = dao.recordIdsUnownedNonPersistent()
        dao.deleteUnownedNonPersistent()
        store.releaseUnpinned(pinned)
    }
}
