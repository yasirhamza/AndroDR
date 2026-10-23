package com.androdr.reporting

import com.androdr.data.model.ScanResult
import com.androdr.ioc.Campaign
import com.androdr.sigma.Finding

/**
 * The findings a report renders, with what the report needs to interpret them: the campaign
 * vocabulary and the loaded rules' scopes and categories ([ReportInputs]). In Phase B the
 * findings are the scan's own (`scan.findings`); a later phase reads them from the findings
 * table without changing the formatter's signature.
 */
class FindingsView(
    val findings: List<Finding>,
    val campaigns: List<Campaign> = emptyList(),
    val ruleScopes: Map<String, RuleScope> = emptyMap(),
    val ruleCategoryById: Map<String, String> = emptyMap(),
) {
    companion object {
        /** [scan]'s findings with the loaded rules' context. Reads small files: off the main thread. */
        fun of(scan: ScanResult, inputs: ReportInputs): FindingsView =
            FindingsView(scan.findings, inputs.campaigns(), inputs.ruleScopes(), inputs.ruleCategoryById())
    }
}
