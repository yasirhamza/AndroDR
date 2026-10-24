package com.androdr.scanner

import com.androdr.sigma.Finding
import java.util.PriorityQueue

/**
 * What a session could not save (spec §5.2, ruling R38): evaluate-only findings whose own no-fact
 * write hit a full disk. Nothing here is a persistence cap — every finding that can be stored is a
 * `scan_finding` row. This only bounds how the findings that could not be stored are *shown*: exact
 * counts by (rule, level), plus the [UNSAVED_DISPLAY_LIMIT] most severe findings as a display sample
 * (severity, then the finding's own event time, then arrival — the retired top-K's order), so an
 * import that overflows a full disk cannot also exhaust the heap.
 */
class UnsavedFindings(private val limit: Int = UNSAVED_DISPLAY_LIMIT) {
    private class Entry(val finding: Finding, val seq: Long) {
        val severity = severityOf(finding.level)
        val time = finding.matchContext["timestamp"]?.toLongOrNull()?.takeIf { it > 0L } ?: 0L
    }

    /** Better first: severity desc, time desc, then arrival. */
    private val better = compareByDescending<Entry> { it.severity }.thenByDescending { it.time }.thenBy { it.seq }
    private val heap = PriorityQueue(better.reversed())
    private var seq = 0L
    private val byRuleLevel = LinkedHashMap<Pair<String, String>, Long>()

    /** How many findings could not be saved (exact). */
    var count: Long = 0
        private set

    fun add(finding: Finding) {
        count++
        val key = finding.ruleId to finding.level
        byRuleLevel[key] = (byRuleLevel[key] ?: 0L) + 1
        heap += Entry(finding, seq++)
        if (heap.size > limit) heap.poll()
    }

    fun addAll(findings: Collection<Finding>) = findings.forEach(::add)

    /** Exact counts of the unsaved findings by (rule id, level). */
    fun countsByRuleLevel(): Map<Pair<String, String>, Long> = byRuleLevel.toMap()

    /** The display sample: at most [limit] findings, most severe first. */
    fun sample(): List<Finding> = heap.sortedWith(better).map { it.finding }

    companion object {
        /**
         * How many unsaved findings are shown. A display bound for data the disk could not take, not a
         * persistence cap (allow-listed by name in NoPersistenceCapsGateTest, ruling R38).
         */
        const val UNSAVED_DISPLAY_LIMIT = 1_000

        private fun severityOf(level: String): Int = when (level.lowercase()) {
            "critical" -> 5
            "high" -> 4
            "medium" -> 3
            "low" -> 2
            "info", "informational" -> 1
            else -> 0
        }
    }
}

/** What [WriteResult] says about findings that could not be saved; [UnsavedSummary.NONE] when all were. */
data class UnsavedSummary(
    val count: Long,
    val byRuleLevel: Map<Pair<String, String>, Long>,
    val sample: List<Finding>,
) {
    companion object {
        val NONE = UnsavedSummary(0, emptyMap(), emptyList())

        fun of(u: UnsavedFindings?): UnsavedSummary =
            if (u == null) NONE else UnsavedSummary(u.count, u.countsByRuleLevel(), u.sample())
    }
}
