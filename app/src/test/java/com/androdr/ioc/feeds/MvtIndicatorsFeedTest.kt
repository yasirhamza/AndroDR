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

    // ── entriesFor (campaign key stamping) ─────────────────────────────────────

    private val spoofYaml = """
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
            name: NSO Group Pegasus Indicators of Compromise
            github:
              owner: attacker
              repo: x
              branch: main
              path: pegasus.stix2
    """.trimIndent()

    // ── allowedCampaigns (PASTA F-004) ─────────────────────────────────────────

    @Test
    fun `a campaign ref pointing outside the upstream registry repos is not fetched`() {
        // indicators.yaml is fetched over a pinned TLS host, but the pin vouches
        // for raw.githubusercontent.com, not for which owner/repo the yaml names.
        // A poisoned yaml must not turn the feed into a fetcher of arbitrary repos.
        val refs = feed.parseIndicatorsYaml(spoofYaml)
        assertEquals(2, refs.size)

        val allowed = feed.allowedCampaigns(refs)

        assertEquals(
            listOf("https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2"),
            allowed.map { it.url },
        )
    }

    @Test
    fun `the three repos the live registry points at are all allowed`() {
        val raw = "https://raw.githubusercontent.com"
        val refs = listOf(
            MvtIndicatorsFeed.CampaignRef("a", "$raw/mvt-project/mvt-indicators/main/x/x.stix2"),
            MvtIndicatorsFeed.CampaignRef("b", "$raw/AmnestyTech/investigations/master/x/x.stix2"),
            MvtIndicatorsFeed.CampaignRef("c", "$raw/AssoEchap/stalkerware-indicators/master/generated/sw.stix2"),
        )
        assertEquals(refs, feed.allowedCampaigns(refs))
    }

    @Test
    fun `duplicate refs collapse and the registry cannot schedule more than the ref cap`() {
        // A per-response size cap alone is defeated by a registry listing the same
        // allowed file thousands of times: N fetches x 16 MB. The live registry has
        // 19 refs; the cap is a multiple of that, and duplicates by URL count once.
        val many = (1..200).map {
            MvtIndicatorsFeed.CampaignRef(
                "c$it", "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/$it.stix2",
            )
        }
        val dupes = List(50) { many[0] }

        assertEquals(1, feed.allowedCampaigns(dupes).size)
        assertEquals(MvtIndicatorsFeed.MAX_CAMPAIGN_REFS, feed.allowedCampaigns(many).size)
        assertTrue(MvtIndicatorsFeed.MAX_CAMPAIGN_REFS in 19..128)
    }

    @Test
    fun `a repo name that merely starts with an allowed one is not allowed`() {
        val lookalike = MvtIndicatorsFeed.CampaignRef(
            "x", "https://raw.githubusercontent.com/mvt-project/mvt-indicators-evil/main/x.stix2",
        )
        assertTrue(feed.allowedCampaigns(listOf(lookalike)).isEmpty())
    }

    @Test
    fun `entriesFor stamps the compiled key only on the real Pegasus collection`() {
        val refs = feed.parseIndicatorsYaml(spoofYaml)
        assertEquals(2, refs.size)
        val real = feed.entriesFor(refs[0], singleDomainStix2, 1L)
        val spoof = feed.entriesFor(refs[1], singleDomainStix2, 1L)
        assertTrue(real.isNotEmpty())
        assertTrue(real.all { it.campaignKey == "pegasus" })
        assertTrue(spoof.isNotEmpty())
        assertTrue(spoof.all { it.campaignKey == "" })
    }
}
