package com.androdr.sigma

import com.androdr.data.model.CveEntity

data class EvidenceResult(
    val evidence: Evidence,
    val titleVars: Map<String, String>,
    val remediationVars: Map<String, String>
)

fun interface EvidenceProvider {
    fun provide(rule: SigmaRule, record: Map<String, Any?>): List<EvidenceResult>
}

class CveEvidenceProvider(private val allRules: List<SigmaRule>) : EvidenceProvider {
    private val campaignMap: Map<String, List<String>> by lazy { buildCampaignMap() }

    override fun provide(rule: SigmaRule, record: Map<String, Any?>): List<EvidenceResult> {
        val rawList = record["unpatched_cves"] as? List<*> ?: return emptyList()
        val cves = rawList.filterIsInstance<CveEntity>()
        if (cves.isEmpty()) return emptyList()
        val cveEvidences = cves.map { cve ->
            CveEvidence(
                cveId = cve.cveId, description = cve.description, severity = cve.severity,
                patchLevel = cve.fixedInPatchLevel, campaigns = campaignMap[cve.cveId] ?: emptyList(),
                dateAdded = cve.cisaDateAdded)
        }
        val campaignCount = cveEvidences.count { it.campaigns.isNotEmpty() }
        val targetPatchLevel = cves.maxOf { it.fixedInPatchLevel }
        val evidence = Evidence.CveList(cves = cveEvidences, targetPatchLevel = targetPatchLevel, campaignCount = campaignCount)
        val titleVars = mapOf("count" to cves.size.toString(), "campaign_count" to campaignCount.toString())
        val remediationVars = mapOf("target_patch_level" to targetPatchLevel, "count" to cves.size.toString(), "campaign_count" to campaignCount.toString())
        return listOf(EvidenceResult(evidence, titleVars, remediationVars))
    }

    private fun buildCampaignMap(): Map<String, List<String>> {
        val map = mutableMapOf<String, MutableList<String>>()
        for (rule in allRules) {
            val campaign = rule.tags.firstOrNull { it.startsWith("campaign.") }?.removePrefix("campaign.") ?: continue
            for (selection in rule.detection.selections.values) {
                for (matcher in selection.fieldMatchers) {
                    if (matcher.fieldName == "unpatched_cve_id") {
                        for (value in matcher.values) {
                            map.getOrPut(value.toString()) { mutableListOf() }.add(campaign)
                        }
                    }
                }
            }
        }
        return map
    }
}
