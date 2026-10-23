package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.SignalMember
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.HashKeys

/**
 * What a correlation atom points at (spec §6): a `forensic_timeline` row ([Row]) or a stored
 * telemetry fact ([Fact]). The two id spaces are separate, so a row and a fact with the same
 * numeric id are different atoms. Ordered by `(kind, id)`, the order `signal_member` pages use.
 */
sealed interface AtomRef : Comparable<AtomRef> {
    val kind: Int
    val id: Long

    override fun compareTo(other: AtomRef): Int =
        if (kind != other.kind) kind.compareTo(other.kind) else id.compareTo(other.id)

    /** The `kind:id` form the canonical correlation id and the CSV `member_refs` column use. */
    fun encoded(): String = "$kind:$id"

    companion object {
        fun of(kind: Int, id: Long): AtomRef = if (kind == SignalMember.KIND_FACT) Fact(id) else Row(id)
    }
}

/** A `forensic_timeline` row. */
data class Row(override val id: Long) : AtomRef {
    override val kind: Int get() = SignalMember.KIND_ROW
}

/** A `telemetry_record` fact. */
data class Fact(override val id: Long) : AtomRef {
    override val kind: Int get() = SignalMember.KIND_FACT
}

/**
 * One correlation input (spec §5.2 Correlation inputs): a timeline row or an exact-precision fact
 * in an atom-bound category, reduced to what the correlator reads.
 */
data class TimelineAtom(
    val ref: AtomRef,
    val category: String,
    val timestamp: Long,
    val packageName: String,
    val ruleId: String,
    val telemetrySource: TelemetrySource,
)

/** This row as a [Row] atom. */
fun ForensicTimelineEvent.asAtom(): TimelineAtom = TimelineAtom(
    ref = Row(id), category = category, timestamp = startTimestamp, packageName = packageName,
    ruleId = ruleId, telemetrySource = telemetrySource,
)

/** Canonical signal identity (spec §5.4): no member list is ever stored on the signal row. */
object SignalIdentity {
    /** `ruleId:` + h128 hex over the members sorted by `(kind, id)`, each encoded `kind:id`. */
    fun correlationId(ruleId: String, members: Collection<AtomRef>): String {
        val canonical = members.sorted().joinToString(",") { it.encoded() }
        return "$ruleId:" + HashKeys.h128(canonical).joinToString("") { "%02x".format(it) }
    }
}

/**
 * The correlator's time budget (spec §5.2): a per-(rule, group) deadline and a per-`finish` total
 * deadline that also covers atom binding and grouping. Deadlines are checked, never thrown: the
 * correlator runs inside the finishing transaction, so a cut-off returns normally with what it
 * found. [clock] is injected so tests force the cut-off deterministically.
 */
class CorrelationBudget(
    private val clock: () -> Long,
    private val perGroupMs: Long = PER_GROUP_MS,
    private val totalMs: Long = TOTAL_MS,
) {
    private val totalDeadline: Long = clock().let { if (totalMs == Long.MAX_VALUE) Long.MAX_VALUE else it + totalMs }

    /** True once the total deadline has passed. */
    fun totalExpired(): Boolean = clock() >= totalDeadline

    /** The deadline of a (rule, group) starting now: its own budget, never past the total. */
    fun groupDeadline(): Long {
        val now = clock()
        val own = if (perGroupMs == Long.MAX_VALUE) Long.MAX_VALUE else now + perGroupMs
        return minOf(own, totalDeadline)
    }

    /** True once [deadline] (from [groupDeadline]) has passed. */
    fun expired(deadline: Long): Boolean = clock() >= deadline

    companion object {
        const val PER_GROUP_MS = 2_000L
        const val TOTAL_MS = 5_000L

        /** No deadlines (pure tests of the matching logic). */
        fun unbounded(): CorrelationBudget = CorrelationBudget({ 0L }, Long.MAX_VALUE, Long.MAX_VALUE)
    }
}
