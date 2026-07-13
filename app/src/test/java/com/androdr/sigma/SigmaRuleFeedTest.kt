package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SigmaRuleFeedTest {

    @Test
    fun `parseManifest filters yml lines and ignores comments`() {
        val manifest = """
            # AndroDR SIGMA Rules Manifest
            rules/production/app_risk/androdr-060.yml
            rules/production/device_posture/androdr-061.yml

            # Some comment
            not-a-yml-file.txt
        """.trimIndent()

        val files = SigmaRuleFeed.parseManifest(manifest)

        assertEquals(2, files.size)
        assertEquals("rules/production/app_risk/androdr-060.yml", files[0])
        assertEquals("rules/production/device_posture/androdr-061.yml", files[1])
    }

    @Test
    fun `parseManifest handles flat filenames for backward compatibility`() {
        val manifest = """
            androdr-001.yml
            androdr-002.yml
        """.trimIndent()

        val files = SigmaRuleFeed.parseManifest(manifest)

        assertEquals(2, files.size)
        assertEquals("androdr-001.yml", files[0])
    }

    @Test
    fun `parseManifest returns empty for blank manifest`() {
        val files = SigmaRuleFeed.parseManifest("")
        assertEquals(0, files.size)
    }

    @Test
    fun `parseHashManifest parses sha256sum format`() {
        val manifest = """
            abc123def456  app_scanner/androdr_010.yml
            789fed  device_auditor/androdr_040.yml
            # comment
        """.trimIndent()

        val hashes = SigmaRuleFeed.parseHashManifest(manifest)

        assertEquals(2, hashes.size)
        assertEquals("abc123def456", hashes["app_scanner/androdr_010.yml"])
        assertEquals("789fed", hashes["device_auditor/androdr_040.yml"])
    }

    @Test
    fun `parseHashManifest returns empty for blank input`() {
        assertEquals(0, SigmaRuleFeed.parseHashManifest("").size)
    }

    // --- Integrity decision (fail-closed for the default repo) — #238 ---

    private val yaml = "title: t\nid: androdr-001\n"
    private val goodHash = java.security.MessageDigest.getInstance("SHA-256")
        .digest(yaml.toByteArray()).joinToString("") { "%02x".format(it) }

    @Test
    fun `matching hash is accepted`() {
        val d = SigmaRuleFeed.decideRuleFile("a.yml", yaml, mapOf("a.yml" to goodHash), requireManifest = true)
        assertEquals(SigmaRuleFeed.RuleFileDecision.Accept, d)
    }

    @Test
    fun `mismatched hash is skipped regardless of requireManifest`() {
        for (req in listOf(true, false)) {
            val d = SigmaRuleFeed.decideRuleFile("a.yml", yaml, mapOf("a.yml" to "deadbeef"), requireManifest = req)
            assertTrue("req=$req", d is SigmaRuleFeed.RuleFileDecision.Skip)
        }
    }

    @Test
    fun `file absent from manifest fails closed when manifest required`() {
        // Manifest present (other file listed) but THIS file missing → unverified → skip.
        val d = SigmaRuleFeed.decideRuleFile("a.yml", yaml, mapOf("other.yml" to goodHash), requireManifest = true)
        assertTrue(d is SigmaRuleFeed.RuleFileDecision.Skip)
    }

    @Test
    fun `file absent from manifest is accepted for lenient custom feed`() {
        val d = SigmaRuleFeed.decideRuleFile("a.yml", yaml, mapOf("other.yml" to goodHash), requireManifest = false)
        assertEquals(SigmaRuleFeed.RuleFileDecision.Accept, d)
    }

    @Test
    fun `empty manifest map accepts for lenient custom feed`() {
        val d = SigmaRuleFeed.decideRuleFile("a.yml", yaml, emptyMap(), requireManifest = false)
        assertEquals(SigmaRuleFeed.RuleFileDecision.Accept, d)
    }

    @Test
    fun `empty manifest map fails closed when manifest required (corrupt or missing sha256)`() {
        // A corrupt/garbage rules.sha256 parses to an empty map. It must NOT be
        // treated as "no verification needed" — that would be a fail-open bypass.
        val d = SigmaRuleFeed.decideRuleFile("a.yml", yaml, emptyMap(), requireManifest = true)
        assertTrue(d is SigmaRuleFeed.RuleFileDecision.Skip)
    }
}
