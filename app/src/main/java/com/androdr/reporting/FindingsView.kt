package com.androdr.reporting

import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.FindingsRepository
import com.androdr.ioc.Campaign
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding

/**
 * The findings a report renders, with what the report needs to interpret them: the campaign
 * vocabulary and the loaded rules' scopes and categories ([ReportInputs]). The findings are the
 * scan's own `scan_finding` rows (spec §5.4), streamed and folded ([FindingsDigest], review I1): a
 * finding that would render exactly like an earlier one is one entry whose [count] says how many it
 * stands for, so every count the report prints stays exact and nothing holds a whole import.
 */
class FindingsView(
    val findings: List<Finding>,
    val campaigns: List<Campaign> = emptyList(),
    val ruleScopes: Map<String, RuleScope> = emptyMap(),
    val ruleCategoryById: Map<String, String> = emptyMap(),
    /** How many findings each entry of [findings] stands for (by identity); absent means 1. */
    private val counts: Map<Finding, Int> = emptyMap(),
) {
    /** How many of the scan's findings [f] (an entry of [findings]) stands for. */
    fun count(f: Finding): Int = counts[f] ?: 1

    /** The sum of [count] over [fs]. */
    fun countOf(fs: Iterable<Finding>): Int = fs.sumOf { count(it) }

    /** A [FindingsDigest] result: folded findings and their multiplicities (an identity map). */
    class Folded(val findings: List<Finding>, val counts: Map<Finding, Int>)

    companion object {
        /**
         * [scan]'s findings with the loaded rules' context, streamed from `scan_finding` page by page
         * and folded. The campaign window is fixed first (it decides how IOC observation times fold):
         * the scan's time for a live scan; for an import, its latest stored event ([telemetry]), else
         * its latest IOC observation not after the import — [campaignReferenceTime]'s rule.
         * Reads the database and small files: off the main thread.
         */
        suspend fun of(
            scan: ScanResult, inputs: ReportInputs, findings: FindingsRepository, telemetry: StoredTelemetrySource,
        ): FindingsView {
            val reference = referenceTime(scan, findings, telemetry)
            val digest = FindingsDigest(reference - CAMPAIGN_HIT_WINDOW_MS, scan.timestamp)
            findings.forEachFinding(scan.id) { digest.add(it) }
            val folded = digest.result()
            return FindingsView(
                folded.findings, inputs.campaigns(), inputs.ruleScopes(), inputs.ruleCategoryById(), folded.counts,
            )
        }

        private suspend fun referenceTime(
            scan: ScanResult, findings: FindingsRepository, telemetry: StoredTelemetrySource,
        ): Long {
            if (scan.source == TelemetrySource.LIVE_SCAN) return scan.timestamp
            telemetry.latestEventTime(scan.id, notAfter = scan.timestamp)?.takeIf { it <= scan.timestamp }
                ?.let { return it }
            var latest = 0L
            findings.forEachFinding(scan.id) { f ->
                val t = (f.evidence as? Evidence.IocMatch)?.observedAt ?: 0L
                if (f.category == com.androdr.sigma.FindingCategory.APP_RISK && t > latest && t <= scan.timestamp) {
                    latest = t
                }
            }
            return latest.takeIf { it > 0 } ?: scan.timestamp
        }
    }
}
