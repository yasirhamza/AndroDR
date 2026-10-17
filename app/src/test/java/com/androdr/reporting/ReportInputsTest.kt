package com.androdr.reporting

import com.androdr.ioc.Campaign
import com.androdr.ioc.CampaignRegistry
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.RuleCategory
import com.androdr.sigma.SigmaDetection
import com.androdr.sigma.SigmaDisplay
import com.androdr.sigma.SigmaFieldMatcher
import com.androdr.sigma.SigmaModifier
import com.androdr.sigma.SigmaSelection
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Test

class ReportInputsTest {

    private fun rule(
        id: String,
        category: RuleCategory,
        tags: List<String> = emptyList(),
        service: String = "device_auditor",
        detection: SigmaDetection = SigmaDetection(emptyMap(), "selection"),
        evidenceType: String = "none",
    ) = SigmaRule(
        id = id, title = id, status = "production", description = "", product = "androdr",
        service = service, level = "medium", category = category, tags = tags,
        detection = detection, falsepositives = emptyList(),
        remediation = emptyList(),
        display = SigmaDisplay(category = FindingCategory.DEVICE_POSTURE, evidenceType = evidenceType),
    )

    @Test
    fun `ruleCategoryById maps each loaded rule id to its category name`() {
        val engine = mockk<SigmaRuleEngine> {
            every { getRules() } returns listOf(
                rule("androdr-048", RuleCategory.DEVICE_POSTURE),
                rule("androdr-108", RuleCategory.INCIDENT),
            )
        }
        val inputs = ReportInputs(mockk(relaxed = true), engine)
        assertEquals(
            mapOf("androdr-048" to "DEVICE_POSTURE", "androdr-108" to "INCIDENT"),
            inputs.ruleCategoryById(),
        )
    }

    @Test
    fun `campaigns come from the registry`() {
        val registry = mockk<CampaignRegistry> { every { campaigns() } returns listOf(Campaign("pegasus", "Pegasus")) }
        assertEquals(listOf(Campaign("pegasus", "Pegasus")), ReportInputs(registry, mockk()).campaigns())
    }

    @Test
    fun `ruleScopes resolves campaign tags through aliases and drops unknown ones`() {
        val engine = mockk<SigmaRuleEngine> {
            every { getEnabledRules() } returns listOf(
                rule("androdr-108", RuleCategory.INCIDENT, tags = listOf("attack.t1", "campaign.cytrox")),
                rule("androdr-200", RuleCategory.INCIDENT, tags = listOf("campaign.nobody")),
            )
        }
        val registry = mockk<CampaignRegistry> {
            every { campaigns() } returns listOf(Campaign("predator", "Predator", aliases = listOf("cytrox")))
        }
        val scopes = ReportInputs(registry, engine).ruleScopes()
        assertEquals(RuleScope("device_auditor", setOf("predator"), false), scopes["androdr-108"])
        assertEquals(RuleScope("device_auditor", emptySet(), false), scopes["androdr-200"])
    }

    @Test
    fun `an ioc_match rule with an ioc_lookup matcher carries any campaign`() {
        val iocDetection = SigmaDetection(
            mapOf("selection" to SigmaSelection(
                listOf(SigmaFieldMatcher("domain", SigmaModifier.IOC_LOOKUP, listOf("x"))),
            )),
            "selection",
        )
        val engine = mockk<SigmaRuleEngine> {
            every { getEnabledRules() } returns listOf(
                rule("androdr-003", RuleCategory.INCIDENT, service = "dns_monitor", detection = iocDetection,
                    evidenceType = "ioc_match"),
                rule("androdr-300", RuleCategory.INCIDENT, service = "dns_monitor", detection = iocDetection,
                    evidenceType = "none"),
            )
        }
        val registry = mockk<CampaignRegistry> { every { campaigns() } returns emptyList() }
        val scopes = ReportInputs(registry, engine).ruleScopes()
        assertEquals(RuleScope("dns_monitor", emptySet(), true), scopes["androdr-003"])
        assertEquals(false, scopes.getValue("androdr-300").carriesIocCampaign)
    }

    @Test
    fun `ruleScopes leaves out a disabled rule`() {
        val enabled = rule("androdr-108", RuleCategory.INCIDENT, tags = listOf("campaign.predator"))
        val disabled = rule("androdr-109", RuleCategory.INCIDENT, tags = listOf("campaign.predator"))
        val engine = mockk<SigmaRuleEngine> {
            every { getRules() } returns listOf(enabled, disabled)
            every { getEnabledRules() } returns listOf(enabled)
        }
        val registry = mockk<CampaignRegistry> {
            every { campaigns() } returns listOf(Campaign("predator", "Predator"))
        }
        assertEquals(setOf("androdr-108"), ReportInputs(registry, engine).ruleScopes().keys)
    }
}
