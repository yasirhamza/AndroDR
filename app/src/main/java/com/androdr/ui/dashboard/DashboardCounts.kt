package com.androdr.ui.dashboard

import com.androdr.data.model.RiskLevel
import com.androdr.data.model.ScanWithFindings
import com.androdr.data.model.levelToScore
import com.androdr.data.model.riskOf
import com.androdr.data.repo.CurrentFindingsSummary
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory

/**
 * Every count the Dashboard shows, from one set (spec §5.4 Current findings): the latest live scan's
 * triggered state findings, informational ones left out, plus the OPEN alerts, each counted once.
 * The risk line, the summary tiles, the current-findings line and the guidance all read this, so
 * they cannot disagree: before, the risk line read the scan's raw findings, which counted each DNS
 * detection again as an "app risk" and dropped informational findings the current-findings line kept.
 *
 * [unsaved] is a scan that could not be saved: it has no state rows and opened no alerts, so its own
 * triggered findings answer for it (an older saved scan must not, see [DashboardViewModel.resolveLatest]).
 */
class DashboardCounts private constructor(
    /** The state findings counted: triggered, never informational. */
    val stateFindings: List<Finding>,
    val openAlertCount: Int,
    /** The latest scan's risk from its state findings; null when there is no scan. */
    val scanRisk: RiskLevel?,
) {
    val appRisks: Int get() = stateFindings.count { it.category == FindingCategory.APP_RISK }
    val deviceFlags: Int get() = stateFindings.count { it.category == FindingCategory.DEVICE_POSTURE }
    val warningSigns: Int get() = stateFindings.count { it.category == FindingCategory.CORRELATION }

    /** Current findings: the state findings counted plus one per open alert. */
    val total: Int get() = stateFindings.size + openAlertCount

    val hasCriticalAppRisks: Boolean
        get() = stateFindings.any { it.category == FindingCategory.APP_RISK && it.level.lowercase() == "critical" }

    val hasChains: Boolean get() = warningSigns > 0

    companion object {
        fun of(latestScan: ScanWithFindings?, unsaved: Boolean, current: CurrentFindingsSummary): DashboardCounts {
            val source = if (unsaved && latestScan != null) latestScan.findings else current.stateFindings
            val counted = source.filter { it.triggered && it.level.lowercase() != INFORMATIONAL }
            val risk = latestScan?.let { riskOf(counted.maxOfOrNull { f -> levelToScore(f.level) } ?: 0) }
            return DashboardCounts(counted, current.openAlertCount, risk)
        }

        private const val INFORMATIONAL = "informational"
    }
}
