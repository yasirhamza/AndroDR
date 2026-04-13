package com.androdr.reporting

import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertTrue
import org.junit.Test

class TimelineFormatterTest {

    private val criticalFinding = Finding(
        ruleId = "androdr-001",
        title = "Known Malicious Package",
        level = "critical",
        category = FindingCategory.APP_RISK,
        triggered = true,
        matchContext = mapOf("package_name" to "com.evil.spy")
    )

    private val mediumFinding = Finding(
        ruleId = "androdr-063",
        title = "Microphone Access",
        level = "medium",
        category = FindingCategory.APP_RISK,
        triggered = true,
        matchContext = mapOf("package_name" to "com.test.app"),
        description = "App used microphone",
        remediation = listOf("Review if expected")
    )

    @Test
    fun `verdict shows CLEAN when no triggered findings`() {
        val text = TimelineFormatter.formatTimeline(
            emptyList(), emptyList()
        )
        assertTrue(text.contains("ANALYSIS VERDICT: CLEAN"))
    }

    @Test
    fun `verdict shows CRITICAL THREATS when critical findings present`() {
        val text = TimelineFormatter.formatTimeline(
            emptyList(), listOf(criticalFinding)
        )
        assertTrue(text.contains("ANALYSIS VERDICT: CRITICAL THREATS DETECTED"))
        assertTrue(text.contains("1 critical"))
    }

    @Test
    fun `verdict shows ISSUES FOUND for medium findings`() {
        val text = TimelineFormatter.formatTimeline(
            emptyList(), listOf(mediumFinding)
        )
        assertTrue(text.contains("ANALYSIS VERDICT: ISSUES FOUND"))
        assertTrue(text.contains("1 medium"))
    }

    @Test
    fun `display names resolve in findings section`() {
        val names = mapOf("com.test.app" to "Test App")
        val text = TimelineFormatter.formatTimeline(
            emptyList(), listOf(mediumFinding),
            displayNames = names
        )
        assertTrue("Display name should appear", text.contains("Test App (com.test.app)"))
    }

    @Test
    fun `display names resolve in hash inventory`() {
        val hashes = mapOf("com.whatsapp" to "abc123")
        val names = mapOf("com.whatsapp" to "WhatsApp")
        val text = TimelineFormatter.formatTimeline(
            emptyList(), emptyList(),
            hashByPkg = hashes, displayNames = names
        )
        assertTrue("Display name in inventory", text.contains("WhatsApp"))
        assertTrue("Package name in inventory", text.contains("Package: com.whatsapp"))
    }

    @Test
    fun `output is ASCII only`() {
        val text = TimelineFormatter.formatTimeline(
            emptyList(),
            listOf(criticalFinding, mediumFinding),
            mapOf("com.test" to "hash123")
        )
        val nonAscii = text.filter { it.code > 127 }
        assertTrue("Non-ASCII characters found: $nonAscii", nonAscii.isEmpty())
    }
}
