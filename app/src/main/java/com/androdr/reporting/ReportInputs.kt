package com.androdr.reporting

import com.androdr.ioc.Campaign
import com.androdr.ioc.CampaignRegistry
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
}
