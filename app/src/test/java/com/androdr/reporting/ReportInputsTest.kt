package com.androdr.reporting

import com.androdr.ioc.Campaign
import com.androdr.ioc.CampaignRegistry
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.RuleCategory
import com.androdr.sigma.SigmaDetection
import com.androdr.sigma.SigmaDisplay
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Test

class ReportInputsTest {

    private fun rule(id: String, category: RuleCategory) = SigmaRule(
        id = id, title = id, status = "production", description = "", product = "androdr",
        service = "device_auditor", level = "medium", category = category, tags = emptyList(),
        detection = SigmaDetection(emptyMap(), "selection"), falsepositives = emptyList(),
        remediation = emptyList(), display = SigmaDisplay(category = FindingCategory.DEVICE_POSTURE),
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
}
