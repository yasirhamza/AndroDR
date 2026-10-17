package com.androdr.reporting

import com.androdr.ioc.Campaign
import com.androdr.ioc.CampaignRegistry
import com.androdr.sigma.SigmaModifier
import com.androdr.sigma.SigmaRuleEngine
import javax.inject.Inject
import javax.inject.Singleton

/**
 * What the report needs beyond the scan itself, from one place, so the exported report
 * (ReportExporter) and the one opened from History (HistoryViewModel) can't drift apart.
 */
@Singleton
class ReportInputs @Inject constructor(
    private val campaignRegistry: CampaignRegistry,
    private val sigmaRuleEngine: SigmaRuleEngine,
) {
    /** The mercenary-check rows' vocabulary. Reads a small file: call off the main thread. */
    fun campaigns(): List<Campaign> = campaignRegistry.campaigns()

    /**
     * Each loaded rule's category name, for findings stored before `Finding.ruleCategory`
     * existed: a stored finding whose rule is no longer loaded is simply absent here.
     */
    fun ruleCategoryById(): Map<String, String> =
        sigmaRuleEngine.getRules().associate { it.id to it.category.name }

    /**
     * What each loaded rule can detect: its service, the campaigns its `campaign.*` tags name
     * (aliases folded, unknown names dropped), and whether it can attribute any campaign through an
     * IOC row (`evidence_type: ioc_match` with an `ioc_lookup` matcher). Matches a rule's
     * "could not run" entries to campaigns (#394). Reads a small file: off the main thread.
     */
    fun ruleScopes(): Map<String, RuleScope> {
        val campaigns = campaignRegistry.campaigns()
        val keyByName = HashMap<String, String>()
        campaigns.forEach { keyByName[it.key] = it.key }
        campaigns.forEach { c -> c.aliases.forEach { keyByName.putIfAbsent(it, c.key) } }
        return sigmaRuleEngine.getRules().associate { rule ->
            val tagged = rule.tags.filter { it.startsWith(CAMPAIGN_TAG) }
                .mapNotNull { keyByName[it.removePrefix(CAMPAIGN_TAG).lowercase()] }.toSet()
            val iocCampaign = rule.display.evidenceType == "ioc_match" &&
                rule.detection.selections.values
                    .any { s -> s.fieldMatchers.any { it.modifier == SigmaModifier.IOC_LOOKUP } }
            rule.id to RuleScope(rule.service, tagged, iocCampaign)
        }
    }

    private companion object {
        const val CAMPAIGN_TAG = "campaign."
    }
}
