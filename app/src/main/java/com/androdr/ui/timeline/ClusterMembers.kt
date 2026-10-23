package com.androdr.ui.timeline

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.SignalMemberDao
import com.androdr.data.db.chunkedIn
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.SignalMember
import com.androdr.data.store.DecodedRecord
import com.androdr.data.store.TelemetryReader
import com.androdr.sigma.AtomRef
import com.androdr.sigma.Fact
import com.androdr.sigma.Row
import javax.inject.Inject
import javax.inject.Singleton

/** A correlation-signal member as the Timeline shows it: a timeline row or a stored fact. */
sealed interface TimelineMember {
    val timestamp: Long

    data class RowMember(val row: ForensicTimelineEvent) : TimelineMember {
        override val timestamp: Long get() = row.startTimestamp
    }

    data class FactMember(val record: DecodedRecord) : TimelineMember {
        override val timestamp: Long get() = record.eventTime ?: record.capturedAt
    }
}

/**
 * One page of a signal's members: those still visible, in `(kind, id)` order; [missing] counts the
 * refs of this page whose row or fact is gone (deleted, or hidden by visibility); [next] is the
 * cursor of the following page, null after the last.
 */
data class ClusterPage(val members: List<TimelineMember>, val missing: Int, val next: AtomRef?)

/**
 * Loads a correlation signal's members on demand, page by page (spec §5.4): `signal_member` refs,
 * rows through [ForensicTimelineEventDao] (visible rows only) and facts decoded through
 * [TelemetryReader.records] (visible facts only). A ref whose row or fact is gone is skipped and
 * counted, exactly as the cluster builder always treated a dangling member.
 */
@Singleton
class ClusterMembers @Inject constructor(
    private val members: SignalMemberDao,
    private val rows: ForensicTimelineEventDao,
    private val reader: TelemetryReader,
) {
    suspend fun load(signalRowId: Long, after: AtomRef?, size: Int = PAGE): ClusterPage {
        val refs = members.forSignal(signalRowId, after?.kind, after?.id, size)
        if (refs.isEmpty()) return ClusterPage(emptyList(), 0, null)
        val rowIds = refs.filter { it.kind == SignalMember.KIND_ROW }.map { it.refId }
        val factIds = refs.filter { it.kind == SignalMember.KIND_FACT }.map { it.refId }
        val rowsById = chunkedIn(rowIds) { rows.visibleByIds(it) }.associateBy { it.id }
        val factsById = chunkedIn(factIds) { reader.records(it) }.associateBy { it.factId }
        val found = refs.mapNotNull { ref ->
            if (ref.kind == SignalMember.KIND_ROW) {
                rowsById[ref.refId]?.let { TimelineMember.RowMember(it) }
            } else {
                factsById[ref.refId]?.let { TimelineMember.FactMember(it) }
            }
        }
        val last = refs.last()
        val next: AtomRef? = if (refs.size < size) null else if (last.kind == SignalMember.KIND_ROW) {
            Row(last.refId)
        } else {
            Fact(last.refId)
        }
        return ClusterPage(found, refs.size - found.size, next)
    }

    companion object {
        const val PAGE = 200
    }
}
