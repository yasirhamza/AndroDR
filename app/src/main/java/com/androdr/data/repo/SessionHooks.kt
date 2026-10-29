package com.androdr.data.repo

import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.moreSevereLevel
import com.androdr.data.store.AtomReader
import com.androdr.sigma.CorrelationSignal
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory

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
     * Summary columns (counts, scanner errors) of the completed scan; [totals] counts every finding
     * the session recorded (at finish, with the correlation findings). `triggeredCount` and
     * `maxLevel` are already set on [scan] from [totals].
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

/**
 * Running counts over every finding a session recorded.
 *
 * @property knownMalware findings at level `critical` implying `known_malware` — today's
 *   `ScanResult.knownMalwareCount` definition, triggered or not.
 * @property triggeredByRule triggered findings per rule id (bounded by the rule count).
 * @property maxLevel the most severe triggered level (lowercase), or null.
 * @property riskySideload APP_RISK findings on a sideloaded app (`ScanResult.riskySideloadCount`).
 */
data class FindingTotals(
    val seen: Long = 0,
    val triggered: Long = 0,
    val knownMalware: Int = 0,
    val triggeredByRule: Map<String, Long> = emptyMap(),
    val maxLevel: String? = null,
    val riskySideload: Int = 0,
) {
    /** [scan] with its summary columns from these totals. */
    fun applyTo(scan: ScanResult): ScanResult =
        scan.copy(triggeredCount = triggered.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), maxLevel = maxLevel)

    /** These totals with [findings] counted too. */
    operator fun plus(findings: List<Finding>): FindingTotals =
        FindingCounter(this).also { c -> findings.forEach(c::offer) }.totals()
}

/** Accumulates [FindingTotals] one finding at a time (no finding is held). */
class FindingCounter(start: FindingTotals = FindingTotals()) {
    private var seen = start.seen
    private var triggered = start.triggered
    private var knownMalware = start.knownMalware
    private val byRule = HashMap(start.triggeredByRule)
    private var maxLevel = start.maxLevel
    private var riskySideload = start.riskySideload

    fun offer(finding: Finding) {
        seen++
        if (finding.level == "critical" && "known_malware" in finding.impliesFlags) knownMalware++
        if (finding.category == FindingCategory.APP_RISK && finding.matchContext["is_sideloaded"] == "true") {
            riskySideload++
        }
        if (finding.triggered) {
            triggered++
            byRule[finding.ruleId] = (byRule[finding.ruleId] ?: 0L) + 1
            maxLevel = moreSevereLevel(maxLevel, finding.level)
        }
    }

    fun totals() = FindingTotals(seen, triggered, knownMalware, byRule.toMap(), maxLevel, riskySideload)
}
