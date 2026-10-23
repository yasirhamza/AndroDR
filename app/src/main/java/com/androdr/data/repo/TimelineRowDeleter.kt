package com.androdr.data.repo

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.SignalMemberDao
import com.androdr.data.db.chunkedEach
import com.androdr.data.db.chunkedIn
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
    suspend fun olderThan(cutoff: Long) =
        delete(dao.recordIdsOlderThan(cutoff), dao.signalIdsOlderThan(cutoff)) { dao.deleteOlderThan(cutoff) }

    /** The rows [ids] (the one-time legacy event-row cleanup, C3). */
    suspend fun byIds(ids: List<Long>) {
        if (ids.isEmpty()) return
        delete(chunkedIn(ids) { dao.recordIdsByIds(it) }, chunkedIn(ids) { dao.signalIdsByIds(it) }) {
            chunkedEach(ids) { dao.deleteByIds(it) }
        }
    }

    /** A scan's own non-persistent rows. */
    suspend fun byScanId(scanId: Long) =
        delete(dao.recordIdsByScanId(scanId), dao.signalIdsByScanId(scanId)) { dao.deleteByScanId(scanId) }

    /** "Clear all": non-persistent rows that are scan-less or whose scan no longer exists. */
    suspend fun unownedNonPersistent() = delete(
        dao.recordIdsUnownedNonPersistent(), dao.signalIdsUnownedNonPersistent(),
    ) { dao.deleteUnownedNonPersistent() }

    /**
     * Removes the members of the [signals] about to go, by signal id (primary-key prefix, never a
     * scan of `signal_member`), then the rows, then releases the rows' and the members' fact pins.
     */
    private suspend fun delete(rowPins: List<Long>, signals: List<Long>, deleteRows: suspend () -> Unit) {
        val memberPins = chunkedIn(signals) { members.factRefsOf(it) }
        chunkedEach(signals) { members.deleteForSignals(it) }
        deleteRows()
        store.releaseUnpinned(rowPins + memberPins)
    }
}
