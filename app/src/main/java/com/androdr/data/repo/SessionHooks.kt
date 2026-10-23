package com.androdr.data.repo

import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.Finding
import com.androdr.sigma.StoreRecord

/**
 * What a writer adds to a writer session's finishing transaction in Phases A–C (spec §5.2
 * Interim). Every member has a no-op default; [NONE] is the plain session.
 *
 * Task A7b fills it per writer: the bounded newest-N event-row heaps (fed from [onChunk], whose
 * fact ids let the rows carry `recordId`), the intrusion-log replace-on-reimport sweep
 * ([sweepPrior]), each writer's finding-row shape ([findingRow]) and its summary ([summarize]).
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

    /**
     * First statement of the finishing transaction (e.g. `deletePriorIntrusionLogRows`, excluding
     * [scanId]). Must delete through [TimelineRowDeleter].
     */
    suspend fun sweepPrior(scanId: Long) = Unit

    /**
     * The Timeline row of one triggered finding, built from `Finding.toForensicTimelineEvent` (which
     * carries the finding's `level`); `finish` sets its `recordId` and `scanResultId`.
     */
    fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent =
        finding.toForensicTimelineEvent(scan, isBugreport = scan.source != TelemetrySource.LIVE_SCAN)

    /** Bounded event rows written in the finishing transaction, after the finding rows. */
    fun interimRows(scan: ScanResult): List<ForensicTimelineEvent> = emptyList()

    /**
     * Summary columns (counts, scanner errors) of the completed scan. `scan.findings` holds the
     * kept findings (capped for intrusion-log imports); [totals] counts every finding the session
     * kept or dropped, so a summary never undercounts past the cap.
     */
    fun summarize(scan: ScanResult, totals: FindingTotals): ScanResult = scan

    companion object {
        val NONE: SessionHooks = object : SessionHooks {}
    }
}

/** A finding the session keeps, with the fact its Timeline row pins (null when nothing was stored). */
class KeptFinding(val finding: Finding, val recordId: Long?)

/**
 * Running counts over every finding a session accepted (before any persistence cap).
 *
 * @property knownMalware findings at level `critical` implying `known_malware` — today's
 *   `ScanResult.knownMalwareCount` definition, triggered or not.
 * @property triggeredByRule triggered findings per rule id (bounded by the rule count).
 */
data class FindingTotals(
    val seen: Long = 0,
    val triggered: Long = 0,
    val knownMalware: Int = 0,
    val triggeredByRule: Map<String, Long> = emptyMap(),
)
