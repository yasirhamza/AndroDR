package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class MvtCampaignsTest {
    private val pegasusName = "NSO Group Pegasus Indicators of Compromise"
    // Exactly what MvtIndicatorsFeed.parseIndicatorsYaml builds from MVT's indicators.yaml
    // (owner/repo/branch/path), verified 2026-10-16. Pegasus is hosted by AmnestyTech, not mvt-project.
    private val pegasusUrl = "https://raw.githubusercontent.com/AmnestyTech/investigations/" +
        "master/2021-07-18_nso/pegasus.stix2"
    private val predatorName = "Predator Spyware Indicators of Compromise"
    private val predatorUrl = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/" +
        "main/intellexa_predator/predator.stix2"

    @Test
    fun `exact collection maps to its key`() {
        assertEquals("pegasus", MvtCampaigns.keyFor(pegasusName, pegasusUrl))
        assertEquals("predator", MvtCampaigns.keyFor(predatorName, predatorUrl))
    }

    @Test
    fun `old mvt-project Pegasus path gets no key`() {
        assertNull(MvtCampaigns.keyFor(pegasusName,
            "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2021-07-18_nso/pegasus.stix2"))
    }

    @Test
    fun `near-name or different URL gets no key`() {
        assertNull(MvtCampaigns.keyFor("NSO Group Pegasus Indicators of Compromise 2", pegasusUrl))
        assertNull(MvtCampaigns.keyFor(pegasusName, "https://raw.githubusercontent.com/attacker/x/main/pegasus.stix2"))
        assertNull(MvtCampaigns.keyFor("HaGeZi TIF", "https://example.org/x"))
    }

    @Test
    fun `compiled keys exist in the campaign vocabulary`() {
        val f = listOf(File("third-party/android-sigma-rules/ioc-data/campaigns.yml"),
            File("../third-party/android-sigma-rules/ioc-data/campaigns.yml")).first { it.isFile }
        val keys = Regex("""- key:\s*(\S+)""").findAll(f.readText()).map { it.groupValues[1] }.toSet()
        assertTrue(MvtCampaigns.allKeys().all { it in keys })
    }

    @Test
    fun `compiled map equals the rules repo map`() {
        val f = listOf(File("third-party/android-sigma-rules/validation/mvt-campaign-map.json"),
            File("../third-party/android-sigma-rules/validation/mvt-campaign-map.json")).first { it.isFile }
        val arr = org.json.JSONArray(f.readText())
        val repo = (0 until arr.length()).associate { i ->
            val o = arr.getJSONObject(i); (o.getString("name") to o.getString("url")) to o.getString("key")
        }
        assertEquals(repo, MvtCampaigns.entries())
    }
}
