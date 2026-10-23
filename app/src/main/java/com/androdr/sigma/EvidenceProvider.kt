package com.androdr.sigma

import com.androdr.data.model.CveFields

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
        // Plain maps (ruling R21), so a record read back from the store gives the same evidence.
        val cveEvidences = rawList.mapNotNull { (it as? Map<*, *>)?.let(::cveEvidence) }
        if (cveEvidences.isEmpty()) return emptyList()
        val campaignCount = cveEvidences.count { it.campaigns.isNotEmpty() }
        val targetPatchLevel = cveEvidences.maxOf { it.patchLevel }
        val evidence = Evidence.CveList(
            cves = cveEvidences,
            targetPatchLevel = targetPatchLevel,
            campaignCount = campaignCount
        )
        val titleVars = mapOf(
            "count" to cveEvidences.size.toString(),
            "campaign_count" to campaignCount.toString()
        )
        val remediationVars = mapOf(
            "target_patch_level" to targetPatchLevel,
            "count" to cveEvidences.size.toString(),
            "campaign_count" to campaignCount.toString()
        )
        return listOf(EvidenceResult(evidence, titleVars, remediationVars))
    }

    /** One `unpatched_cves` entry; null when it names no CVE id. A missing text field reads as empty. */
    private fun cveEvidence(m: Map<*, *>): CveEvidence? {
        val id = m[CveFields.CVE_ID] as? String ?: return null
        fun text(key: String) = m[key] as? String ?: ""
        return CveEvidence(
            cveId = id, description = text(CveFields.DESCRIPTION), severity = text(CveFields.SEVERITY),
            patchLevel = text(CveFields.FIXED_IN_PATCH_LEVEL), campaigns = campaignMap[id] ?: emptyList(),
            dateAdded = text(CveFields.CISA_DATE_ADDED))
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
