package com.androdr.data.repo

import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.AtomReader
import com.androdr.sigma.CorrelationSignal
import com.androdr.sigma.Finding

/**
 * What a writer adds to a writer session's finishing transaction (spec §5.2): each writer's
 * finding-row shape ([findingRow]), its other rows ([extraRows]: the live scan's detected
 * changes), the correlation pass ([correlate]), its summary ([summarize]) and the live event
 * watermarks ([watermarks]). Event records are never written to `forensic_timeline` (C3): they
 * live only in the store. Every member has a no-op default; [NONE] is the plain session.
 */
interface SessionHooks {
    /**
     * The Timeline row of one triggered finding, built from `Finding.toForensicTimelineEvent` (which
     * carries the finding's `level`); `finish` sets its `recordId` and `scanResultId`.
     */
    fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent =
        finding.toForensicTimelineEvent(scan, isBugreport = scan.source != TelemetrySource.LIVE_SCAN)

    /**
     * Rows written in the finishing transaction after the finding rows: the live scan's detected
     * changes (first-seen installs, device-admin grants). Never event records (spec §5.6).
     */
    fun extraRows(scan: ScanResult): List<ForensicTimelineEvent> = emptyList()

    /**
     * The correlation pass, inside the finishing transaction after this scan's rows were written
     * (spec §5.2): reads its atoms through [atoms] — this scan's rows are `Row` atoms with their
     * real ids — and returns the signals (with their members, written only to `signal_member`) and
     * the findings they become (#350). Must never throw because of its time budget.
     */
    suspend fun correlate(scan: ScanResult, atoms: AtomReader): Correlation = Correlation.NONE

    /**
     * Summary columns (counts, scanner errors) of the completed scan. `scan.findings` holds the
     * kept findings (capped for intrusion-log imports); [totals] counts every finding the session
     * kept or dropped, so a summary never undercounts past the cap.
     */
    fun summarize(scan: ScanResult, totals: FindingTotals): ScanResult = scan

    /**
     * The event watermarks this session advances, by service (spec §5.2 Watermarks), written in the
     * finishing transaction once the scan is `COMPLETE`, so a rolled-back finish advances nothing.
     * [saveFallback]: the session fell back to evaluate-only, so watermarks stay put. Live scans only.
     */
    fun watermarks(saveFallback: Boolean): Map<String, Long> = emptyMap()

    companion object {
        val NONE: SessionHooks = object : SessionHooks {}
    }
}

/** What [SessionHooks.correlate] found: signal rows to insert and the findings they become. */
data class Correlation(val signals: List<CorrelationSignal>, val findings: List<Finding>) {
    companion object {
        val NONE = Correlation(emptyList(), emptyList())
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
