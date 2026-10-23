package com.androdr.reporting

import com.androdr.data.model.ScanResult
import com.androdr.data.repo.FindingsRepository
import com.androdr.ioc.Campaign
import com.androdr.sigma.Finding

/**
 * The findings a report renders, with what the report needs to interpret them: the campaign
 * vocabulary and the loaded rules' scopes and categories ([ReportInputs]). The findings are the
 * scan's own `scan_finding` rows (spec §5.4), every one of them, read through [FindingsRepository]
 * (a stored finding's `matchContext` rebuilt from its fact).
 */
class FindingsView(
    val findings: List<Finding>,
    val campaigns: List<Campaign> = emptyList(),
    val ruleScopes: Map<String, RuleScope> = emptyMap(),
    val ruleCategoryById: Map<String, String> = emptyMap(),
) {
    companion object {
        /** [scan]'s findings with the loaded rules' context. Reads the database and small files: off main. */
        suspend fun of(scan: ScanResult, inputs: ReportInputs, findings: FindingsRepository): FindingsView =
            FindingsView(
                findings.findingsOf(scan.id), inputs.campaigns(), inputs.ruleScopes(), inputs.ruleCategoryById(),
            )
    }
}
