package com.androdr.scanner

import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.FindingTotals
import com.androdr.data.repo.KeptFinding
import com.androdr.sigma.Finding
import java.util.PriorityQueue

/** The ranking the 1,000-finding persistence cap uses (#342 B3): severity, then the finding's own time. */
internal object FindingRank {
    /** Higher wins; unknown/blank levels rank lowest so they are dropped first. */
    fun severity(level: String): Int = when (level.lowercase()) {
        "critical" -> 5
        "high" -> 4
        "medium" -> 3
        "low" -> 2
        "info", "informational" -> 1
        else -> 0
    }

    /** Event time a finding inherits from its matched record, or 0L ("Unknown"). */
    fun eventTimeMs(finding: Finding): Long =
        finding.matchContext["timestamp"]?.toLongOrNull()?.takeIf { it > 0L } ?: 0L
}

/**
 * A session's kept findings (spec §5.2 Interim), keeping today's scope of the 1,000-finding cap:
 *  - [cap] non-null (intrusion-log imports): a streaming top-K with the same set and order as
 *    [ScanOrchestrator.capTriggeredFindings] on the full list — at most [cap] triggered findings
 *    held at a time, untriggered ones dropped as today;
 *  - [cap] null (live scans, bug-report imports): every finding, in arrival order, as today.
 * [totals] counts every finding offered, before the cap.
 */
class FindingsTopK(private val cap: Int?) {
    private class Entry(val kept: KeptFinding, val seq: Long) {
        val severity = FindingRank.severity(kept.finding.level)
        val time = FindingRank.eventTimeMs(kept.finding)
    }

    /** Better first: severity desc, time desc, then arrival (a stable sort keeps the earlier). */
    private val better =
        compareByDescending<Entry> { it.severity }.thenByDescending { it.time }.thenBy { it.seq }
    private val heap = PriorityQueue(better.reversed())
    private val all = ArrayList<KeptFinding>()
    private var seq = 0L
    private var seen = 0L
    private var triggered = 0L
    private var knownMalware = 0
    private val byRule = HashMap<String, Long>()

    fun offer(finding: Finding, recordId: Long?) {
        count(finding)
        val kept = KeptFinding(finding, recordId)
        when {
            cap == null -> all += kept
            !finding.triggered -> Unit
            else -> {
                heap += Entry(kept, seq++)
                if (heap.size > cap) heap.poll()
            }
        }
    }

    /** Capped: the kept triggered findings, input order below the cap and ranked above it. Uncapped: all. */
    fun result(): List<KeptFinding> {
        if (cap == null) return all.toList()
        val entries = heap.toMutableList()
        if (triggered <= cap) entries.sortBy { it.seq } else entries.sortWith(better)
        return entries.map { it.kept }
    }

    fun totals() = FindingTotals(seen, triggered, knownMalware, byRule.toMap())

    private fun count(finding: Finding) {
        seen++
        if (finding.level == "critical" && "known_malware" in finding.impliesFlags) knownMalware++
        if (finding.triggered) {
            triggered++
            byRule[finding.ruleId] = (byRule[finding.ruleId] ?: 0L) + 1
        }
    }

    companion object {
        /** Today's cap scope: only intrusion-log imports are capped (#342 B3). */
        fun forSource(source: TelemetrySource): FindingsTopK {
            val capped = source == TelemetrySource.INTRUSION_LOG_IMPORT
            return FindingsTopK(if (capped) ScanOrchestrator.FINDINGS_PERSIST_CAP else null)
        }
    }
}
