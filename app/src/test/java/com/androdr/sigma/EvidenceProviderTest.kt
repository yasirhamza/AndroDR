package com.androdr.sigma

import com.androdr.data.model.CveEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceProviderTest {
    private fun makeRule(
        tags: List<String> = emptyList(),
        evidenceType: String = "cve_list",
        category: RuleCategory = RuleCategory.INCIDENT,
    ) = SigmaRule(
        id = "androdr-047", title = "CVE test", status = "production",
        description = "Test", product = "androdr", service = "device_auditor",
        level = "critical", category = category, tags = tags,
        detection = SigmaDetection(emptyMap(), "selection"),
        falsepositives = emptyList(),
        remediation = listOf("Update to {target_patch_level} or later."),
        display = SigmaDisplay(evidenceType = evidenceType)
    )

    private fun makeCampaignRule(
        campaignTag: String,
        cveIds: List<String>,
        category: RuleCategory = RuleCategory.INCIDENT,
    ) = SigmaRule(
        id = "androdr-048", title = "Campaign", status = "production",
        description = "", product = "androdr", service = "device_auditor",
        level = "critical", category = category, tags = listOf(campaignTag),
        detection = SigmaDetection(
            mapOf("selection" to SigmaSelection(
                listOf(SigmaFieldMatcher("unpatched_cve_id", SigmaModifier.CONTAINS, cveIds))
            )), "selection"
        ),
        falsepositives = emptyList(), remediation = emptyList(),
        display = SigmaDisplay(evidenceType = "cve_list")
    )

    @Test
    fun `produces CveList evidence with correct count`() {
        val cves = listOf(
            CveEntity("CVE-A", "desc a", "CRITICAL", "2024-11-05", "2024-10-01", true, "Google", "Android", 0),
            CveEntity("CVE-B", "desc b", "HIGH", "2024-10-05", "2024-09-01", true, "Google", "Android", 0))
        val provider = CveEvidenceProvider(emptyList())
        val record = mapOf<String, Any?>("unpatched_cves" to cves)
        val results = provider.provide(makeRule(), record)
        assertEquals(1, results.size)
        val evidence = results[0].evidence as Evidence.CveList
        assertEquals(2, evidence.cves.size)
        assertEquals("2024-11-05", evidence.targetPatchLevel)
    }

    @Test
    fun `attaches campaign tags from campaign rules`() {
        val cves = listOf(
            CveEntity("CVE-2023-41064", "desc", "CRITICAL", "2024-01-05", "", true, "Google", "Android", 0),
            CveEntity("CVE-OTHER", "desc", "HIGH", "2024-02-05", "", true, "Google", "Android", 0))
        val campaignRules = listOf(makeCampaignRule("campaign.pegasus", listOf("CVE-2023-41064")))
        val provider = CveEvidenceProvider(campaignRules)
        val record = mapOf<String, Any?>("unpatched_cves" to cves)
        val results = provider.provide(makeRule(), record)
        val evidence = results[0].evidence as Evidence.CveList
        assertEquals(listOf("pegasus"), evidence.cves.find { it.cveId == "CVE-2023-41064" }!!.campaigns)
        assertEquals(1, evidence.campaignCount)
        assertTrue(evidence.cves.find { it.cveId == "CVE-OTHER" }!!.campaigns.isEmpty())
    }

    @Test
    fun `target patch level is max across unpatched CVEs`() {
        val cves = listOf(
            CveEntity("CVE-A", "a", "HIGH", "2024-09-05", "", true, "Google", "Android", 0),
            CveEntity("CVE-B", "b", "HIGH", "2025-01-05", "", true, "Google", "Android", 0),
            CveEntity("CVE-C", "c", "MEDIUM", "2024-11-05", "", true, "Google", "Android", 0))
        val provider = CveEvidenceProvider(emptyList())
        val results = provider.provide(makeRule(), mapOf("unpatched_cves" to cves))
        assertEquals("2025-01-05", (results[0].evidence as Evidence.CveList).targetPatchLevel)
    }

    @Test
    fun `empty CVE list returns empty results`() {
        val provider = CveEvidenceProvider(emptyList())
        val results = provider.provide(makeRule(), mapOf("unpatched_cves" to emptyList<CveEntity>()))
        assertTrue(results.isEmpty())
    }

    @Test
    fun `template vars include count and campaign_count`() {
        val cves = listOf(CveEntity("CVE-A", "a", "HIGH", "2024-11-05", "", true, "Google", "Android", 0))
        val provider = CveEvidenceProvider(emptyList())
        val results = provider.provide(makeRule(), mapOf("unpatched_cves" to cves))
        assertEquals("1", results[0].titleVars["count"])
        assertEquals("0", results[0].titleVars["campaign_count"])
        assertEquals("2024-11-05", results[0].remediationVars["target_patch_level"])
    }
}
