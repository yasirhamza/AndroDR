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
    fun `every allowed repo accepts a well-formed branch and nested path`() {
        val refs = MvtIndicatorsFeed.ALLOWED_CAMPAIGN_PREFIXES.mapIndexed { i, prefix ->
            MvtIndicatorsFeed.CampaignRef("c$i", "${prefix}main/2021-07-18_nso/pegasus.stix2")
        }
        assertEquals(3, refs.size)
        assertEquals(refs, feed.allowedCampaigns(refs))
    }

    @Test
    fun `dot segments and URL metacharacters in branch or path are not allowed`() {
        // raw.githubusercontent.com answers `..` with a 307 to the normalised path
        // (probed 2026-11-06), and OkHttp normalises dot segments client-side, so a
        // prefix check on the assembled URL is not enough (security review S1).
        val allowed = MvtIndicatorsFeed.ALLOWED_CAMPAIGN_PREFIXES.first()
        val hostile = listOf(
            "../../evil/repo/main/x.stix2",
            "main/../../evil/repo/main/x.stix2",
            "%2e%2e/%2e%2e/evil/repo/main/x.stix2",
            "main/x.stix2?x=1",
            "main/x.stix2#frag",
            "main\\x.stix2",
            "main//x.stix2",
            "main/./x.stix2",
        ).map { MvtIndicatorsFeed.CampaignRef("h", allowed + it) }

        assertEquals(emptyList<Any>(), feed.allowedCampaigns(hostile))
    }

    @Test
    fun `the response cap leaves headroom over the largest live collection`() {
        // Measured 2026-11-06: stalkerware.stix2 is 4.68 MiB; next is 2.2 MiB.
        assertTrue(MvtIndicatorsFeed.MAX_RESPONSE_CHARS >= 2 * 4_910_000)
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
