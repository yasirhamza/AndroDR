package com.androdr.scanner

import com.androdr.data.model.ForensicTimelineEvent
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
 *    [ScanOrchestrator.Companion.capTriggeredFindings] on the full list — at most [cap] triggered findings
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

/**
 * The newest [cap] items by time, with today's tie order (`sortedByDescending { time }.take(cap)` over
 * the arrival order keeps, among equal times, the earlier arrival); at most [cap] held at a time.
 * [cap] null keeps every item in arrival order.
 */
internal class NewestN<T>(private val cap: Int?, private val time: (T) -> Long) {
    private class Entry<T>(val item: T, val recordId: Long?, val time: Long, val seq: Long)

    /** Root = the entry dropped first: the oldest time, then the latest arrival. */
    private val heap = PriorityQueue<Entry<T>>(compareBy<Entry<T>> { it.time }.thenByDescending { it.seq })
    private val all = ArrayList<Entry<T>>()
    private var seq = 0L

    fun offer(item: T, recordId: Long?) {
        val entry = Entry(item, recordId, time(item), seq++)
        if (cap == null) {
            all += entry
            return
        }
        heap += entry
        if (heap.size > cap) heap.poll()
    }

    /** Capped: newest first (time desc, then arrival). Uncapped: arrival order. */
    fun result(): List<Pair<T, Long?>> {
        val entries = if (cap == null) {
            all
        } else {
            heap.sortedWith(compareByDescending<Entry<T>> { it.time }.thenBy { it.seq })
        }
        return entries.map { it.item to it.recordId }
    }
}

/**
 * Today's interim event rows (spec §5.2 Interim, until Task C3): one bounded [NewestN] per service,
 * filled chunk by chunk. A writer [stage]s a chunk's typed records just before appending the chunk;
 * the session's `onChunk` then pairs them with their fact ids, so each row carries `recordId`.
 *
 * A record the store did not observe for this scan (an exact duplicate within an import) gets no
 * row, as the parser's old seen-set guaranteed — unless its service keeps unobserved records (the
 * live usage rows, which are replaced wholesale every scan as today). In evaluate-only mode nothing
 * is stored, so rows are kept with a null `recordId`.
 */
class InterimTimelineRows {
    private class Kind<T>(
        val heap: NewestN<T>,
        val keepUnobserved: Boolean,
        val row: (T, Long) -> ForensicTimelineEvent,
    ) {
        var staged: List<T>? = null
        var unobserved = 0
    }

    private val kinds = LinkedHashMap<String, Kind<*>>()

    /** Registers [service]'s heap; rows come out in registration order. */
    fun <T> register(
        service: String, cap: Int?, keepUnobserved: Boolean, time: (T) -> Long,
        row: (item: T, scanId: Long) -> ForensicTimelineEvent,
    ) {
        kinds[service] = Kind(NewestN(cap, time), keepUnobserved, row)
    }

    /** Stages [items], index for index the next chunk appended for [service]. */
    fun <T> stage(service: String, items: List<T>) {
        kind<T>(service)?.staged = items
    }

    /** Pairs the staged chunk of [service] with its fact ids (null/null when evaluate-only). */
    fun onChunk(service: String, factIds: LongArray?, observed: BooleanArray?) {
        val kind = kind<Any?>(service) ?: return
        val items = kind.staged ?: return
        kind.staged = null
        items.forEachIndexed { i, item ->
            val seen = observed?.getOrNull(i) ?: true
            if (!seen) kind.unobserved++
            if (seen || kind.keepUnobserved) kind.heap.offer(item, factIds?.getOrNull(i))
        }
    }

    /** Records of [service] the store dropped as exact duplicates within this scan. */
    fun unobserved(service: String): Int = kinds[service]?.unobserved ?: 0

    /** Every kept row, per service in registration order, each with its `recordId` and [scanId]. */
    fun rows(scanId: Long): List<ForensicTimelineEvent> = kinds.values.flatMap { rowsOf(it, scanId) }

    private fun <T> rowsOf(kind: Kind<T>, scanId: Long): List<ForensicTimelineEvent> =
        kind.heap.result().map { (item, recordId) -> kind.row(item, scanId).copy(recordId = recordId) }

    @Suppress("UNCHECKED_CAST")
    private fun <T> kind(service: String): Kind<T>? = kinds[service] as? Kind<T>
}
