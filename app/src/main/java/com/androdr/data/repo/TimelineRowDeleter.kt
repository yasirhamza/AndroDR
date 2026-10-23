package com.androdr.data.repo

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.SignalMemberDao
import com.androdr.data.store.TelemetryStore
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The only caller of `ForensicTimelineEventDao`'s row deletes. A `forensic_timeline` row with a
 * `recordId` pins that fact (spec §5.1 Pins), so each delete reads the facts its rows pin, deletes
 * the rows, and passes those facts to [TelemetryStore.releaseUnpinned] — which removes any left with
 * no observation and no other pin.
 *
 * A deleted signal row takes its `signal_member` rows with it (spec §5.4, §5.6), and the facts
 * those members pinned are released the same way.
 *
 * Transaction-agnostic: every function must run inside the caller's Room transaction, so the
 * release commits (or rolls back) with the delete.
 */
@Singleton
class TimelineRowDeleter @Inject constructor(
    private val dao: ForensicTimelineEventDao,
    private val store: TelemetryStore,
    private val members: SignalMemberDao,
) {
    /** The 30-day prune of non-persistent rows (audit/closure rows are kept). */
    suspend fun olderThan(cutoff: Long) {
        val pinned = dao.recordIdsOlderThan(cutoff)
        dao.deleteOlderThan(cutoff)
        release(pinned)
    }

    suspend fun bySource(source: String) {
        val pinned = dao.recordIdsBySource(source)
        dao.deleteBySource(source)
        release(pinned)
    }

    /** Rows of [source] stamped in `[since, until]` (the live scan's re-read usage window). */
    suspend fun bySourceBetween(source: String, since: Long, until: Long) {
        val pinned = dao.recordIdsBySourceBetween(source, since, until)
        dao.deleteBySourceBetween(source, since, until)
        release(pinned)
    }

    /** A scan's own non-persistent rows. */
    suspend fun byScanId(scanId: Long) {
        val pinned = dao.recordIdsByScanId(scanId)
        dao.deleteByScanId(scanId)
        release(pinned)
    }

    /** "Clear all": non-persistent rows that are scan-less or whose scan no longer exists. */
    suspend fun unownedNonPersistent() {
        val pinned = dao.recordIdsUnownedNonPersistent()
        dao.deleteUnownedNonPersistent()
        release(pinned)
    }

    /** Removes the members of signals just deleted, then releases their facts and the rows' pins. */
    private suspend fun release(rowPins: List<Long>) {
        val memberPins = members.orphanFactRefs()
        members.deleteOrphans()
        store.releaseUnpinned(rowPins + memberPins)
    }
}
