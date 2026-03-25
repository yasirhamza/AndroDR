package com.androdr.ioc.feeds

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MvtIndicatorsFeedTest {

    private val feed = MvtIndicatorsFeed()

    // ── parseIndicatorsYaml ────────────────────────────────────────────────────

    private val sampleYaml = """
        indicators:
          -
            type: github
            name: NSO Group Pegasus Indicators of Compromise
            github:
              owner: AmnestyTech
              repo: investigations
              branch: master
              path: 2021-07-18_nso/pegasus.stix2
          -
            type: github
            name: Predator Spyware Indicators of Compromise
            github:
              owner: mvt-project
              repo: mvt-indicators
              branch: main
              path: intellexa_predator/predator.stix2
          -
            type: other
            name: Some other feed
    """.trimIndent()

    @Test
    fun `parseIndicatorsYaml extracts github-type entries only`() {
        val campaigns = feed.parseIndicatorsYaml(sampleYaml)
        assertEquals(2, campaigns.size)
    }

    @Test
    fun `parseIndicatorsYaml builds correct raw github URLs`() {
        val campaigns = feed.parseIndicatorsYaml(sampleYaml)
        assertEquals(
            "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2",
            campaigns[0].url
        )
        assertEquals(
            "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/intellexa_predator/predator.stix2",
            campaigns[1].url
        )
    }

    @Test
    fun `parseIndicatorsYaml captures campaign names`() {
        val campaigns = feed.parseIndicatorsYaml(sampleYaml)
        assertEquals("NSO Group Pegasus Indicators of Compromise", campaigns[0].name)
        assertEquals("Predator Spyware Indicators of Compromise", campaigns[1].name)
    }

    @Test
    fun `parseIndicatorsYaml returns empty list for empty yaml`() {
        assertTrue(feed.parseIndicatorsYaml("").isEmpty())
    }

    // ── parseStix2 ─────────────────────────────────────────────────────────────

    private val singleDomainStix2 = """
        {
          "type": "bundle",
          "objects": [
            {
              "type": "indicator",
              "pattern_type": "stix",
              "pattern": "[domain-name:value = 'weather4free.com']",
              "indicator_types": ["malicious-activity"]
            }
          ]
        }
    """.trimIndent()

    private val compoundOrStix2 = """
        {
          "type": "bundle",
          "objects": [
            {
              "type": "indicator",
              "pattern_type": "stix",
              "pattern": "[domain-name:value = 'foo.com' OR domain-name:value = 'bar.com']",
              "indicator_types": ["malicious-activity"]
            }
          ]
        }
    """.trimIndent()

    private val mixedStix2 = """
        {
          "type": "bundle",
          "objects": [
            {
              "type": "malware",
              "name": "Pegasus"
            },
            {
              "type": "indicator",
              "pattern_type": "stix",
              "pattern": "[domain-name:value = 'spyware.io']",
              "indicator_types": ["malicious-activity"]
            },
            {
              "type": "indicator",
              "pattern_type": "pcre",
              "pattern": ".*spyware.*",
              "indicator_types": ["malicious-activity"]
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `parseStix2 extracts single domain from simple indicator`() {
        val domains = feed.parseStix2(singleDomainStix2, "NSO Group Pegasus", "mvt_pegasus", 1000L)
        assertEquals(1, domains.size)
        assertEquals("weather4free.com", domains[0].domain)
    }

    @Test
    fun `parseStix2 extracts multiple domains from compound OR pattern`() {
        val domains = feed.parseStix2(compoundOrStix2, "Predator", "mvt_predator", 1000L)
        assertEquals(2, domains.size)
        val domainNames = domains.map { it.domain }.toSet()
        assertEquals(setOf("foo.com", "bar.com"), domainNames)
    }

    @Test
    fun `parseStix2 ignores non-stix pattern types and non-indicator objects`() {
        val domains = feed.parseStix2(mixedStix2, "NSO Group Pegasus", "mvt_pegasus", 1000L)
        assertEquals(1, domains.size)
        assertEquals("spyware.io", domains[0].domain)
    }

    @Test
    fun `parseStix2 sets correct metadata on entries`() {
        val domains = feed.parseStix2(singleDomainStix2, "NSO Group Pegasus", "mvt_pegasus", 9999L)
        val entry = domains[0]
        assertEquals("NSO Group Pegasus", entry.campaignName)
        assertEquals("CRITICAL", entry.severity)
        assertEquals("mvt_pegasus", entry.source)
        assertEquals(9999L, entry.fetchedAt)
    }

    @Test
    fun `parseStix2 returns empty list for malformed JSON`() {
        assertTrue(feed.parseStix2("not json", "test", "mvt_test", 0L).isEmpty())
    }
}
