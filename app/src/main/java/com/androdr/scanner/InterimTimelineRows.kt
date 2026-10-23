package com.androdr.scanner

import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.Finding
import com.androdr.sigma.StoreRecord
import java.util.PriorityQueue

/**
 * What a writer adds to a [ChunkedScanWriter.Session]'s finishing transaction in Phases A–C
 * (spec §5.2 Interim). Every member has a no-op default; [NONE] is the plain session.
 *
 * Task A7b fills it per writer: the bounded newest-N event-row heaps (fed from [onChunk], whose
 * fact ids let the rows carry `recordId`), the intrusion-log replace-on-reimport sweep
 * ([sweepPrior]) and each writer's finding-row shape ([findingRow]).
 */
interface SessionHooks {
    /**
     * After each chunk: its fact ids and observed-this-scan flags by chunk index, or null for
     * both when the chunk was only evaluated (evaluate-only mode).
     */
    @Suppress("LongParameterList")
    fun onChunk(
        service: String, source: TelemetrySource, chunk: List<StoreRecord>, firstOrdinal: Int,
        factIds: LongArray?, observed: BooleanArray?,
    ) = Unit

    /** First statement of the finishing transaction (e.g. `deletePriorIntrusionLogRows`, excluding [scanId]). */
    suspend fun sweepPrior(scanId: Long) = Unit

    /**
     * The Timeline row of one triggered finding, built from `Finding.toForensicTimelineEvent` (which
     * carries the finding's `level`); `finish` sets its `recordId` and `scanResultId`.
     */
    fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent =
        finding.toForensicTimelineEvent(scan, isBugreport = scan.source != TelemetrySource.LIVE_SCAN)

    /** Bounded event rows written in the finishing transaction, after the finding rows. */
    fun interimRows(scan: ScanResult): List<ForensicTimelineEvent> = emptyList()

    /** Summary columns (counts, scanner errors) of the completed scan, given its kept findings. */
    fun summarize(scan: ScanResult): ScanResult = scan

    companion object {
        val NONE: SessionHooks = object : SessionHooks {}
    }
}

/** A finding the session keeps, with the fact its Timeline row pins (null when nothing was stored). */
class KeptFinding(val finding: Finding, val recordId: Long?)

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
 * Streaming top-K over a session's findings: the same set and order as
 * [ScanOrchestrator.capTriggeredFindings] on the full list, holding at most [cap] triggered
 * findings at a time. Untriggered (safe-state) findings keep their first [cap] in order.
 */
class FindingsTopK(private val cap: Int = ScanOrchestrator.FINDINGS_PERSIST_CAP) {
    private class Entry(val kept: KeptFinding, val seq: Long) {
        val severity = FindingRank.severity(kept.finding.level)
        val time = FindingRank.eventTimeMs(kept.finding)
    }

    /** Better first: severity desc, time desc, then arrival (a stable sort keeps the earlier). */
    private val better = compareByDescending<Entry> { it.severity }.thenByDescending { it.time }.thenBy { it.seq }
    private val heap = PriorityQueue(better.reversed())
    private val untriggered = ArrayList<KeptFinding>()
    private var seq = 0L

    /** Triggered findings offered so far. */
    var triggeredSeen: Long = 0
        private set

    fun offer(finding: Finding, recordId: Long?) {
        val kept = KeptFinding(finding, recordId)
        if (!finding.triggered) {
            if (untriggered.size < cap) untriggered += kept
            return
        }
        triggeredSeen++
        heap += Entry(kept, seq++)
        if (heap.size > cap) heap.poll()
    }

    /** The kept triggered findings (input order below the cap, ranked above it), then the untriggered. */
    fun result(): List<KeptFinding> {
        val entries = heap.toMutableList()
        if (triggeredSeen <= cap) entries.sortBy { it.seq } else entries.sortWith(better)
        return entries.map { it.kept } + untriggered
    }
}
