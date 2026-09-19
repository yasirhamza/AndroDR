package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * `display.category` decides which SECTION of the report and UI a finding is shown
 * in. Until #364/#367 the parser defaulted an absent or unknown value to
 * `device_posture`, so a typo -- or a rule that simply forgot the field -- silently
 * filed its findings under "device settings". A rule that produces findings must
 * say where they go; the only rules that may omit it are atoms, which declare
 * `display.suppress_finding: true` and produce no findings at all.
 *
 * Mirrors SigmaRuleParserCategoryEnforcementTest, which does the same for the
 * top-level `category:`.
 */
class SigmaRuleParserDisplayCategoryEnforcementTest {

    private fun rule(display: String?) = buildString {
        appendLine("title: Display enforcement probe")
        appendLine("id: test-display-enforce")
        appendLine("status: experimental")
        appendLine("category: incident")
        appendLine("logsource:")
        appendLine("    product: androdr")
        appendLine("    service: app_scanner")
        appendLine("detection:")
        appendLine("    selection:")
        appendLine("        is_sideloaded: true")
        appendLine("    condition: selection")
        appendLine("level: medium")
        if (display != null) {
            appendLine("display:")
            display.lines().filter { it.isNotBlank() }.forEach { appendLine("    ${it.trim()}") }
        }
    }

    private fun assertRejected(yaml: String, why: String) {
        try {
            SigmaRuleParser.parse(yaml)
            fail("Expected SigmaRuleParseException: $why")
        } catch (e: SigmaRuleParseException) {
            assertTrue("message should name display.category: ${e.message}", e.message!!.contains("display.category"))
        }
    }

    @Test
    fun `display category absent on a finding-producing rule is rejected`() {
        assertRejected(rule("icon: warning"), "no display.category, not suppressed")
    }

    @Test
    fun `display block absent entirely on a finding-producing rule is rejected`() {
        assertRejected(rule(null), "no display block at all")
    }

    @Test
    fun `unknown display category is rejected`() {
        assertRejected(rule("category: bogus_bucket"), "value outside the schema enum")
    }

    @Test
    fun `network is no longer a display category`() {
        // Zero rules in either repo ever used it and nothing rendered it -- a bucket
        // a finding could be filed into and never seen. Removed on both sides.
        assertRejected(rule("category: network"), "dead bucket")
    }

    @Test
    fun `display category is parsed to the typed enum`() {
        val app = requireNotNull(SigmaRuleParser.parse(rule("category: app_risk")))
        val posture = requireNotNull(SigmaRuleParser.parse(rule("category: device_posture")))

        assertEquals(FindingCategory.APP_RISK, app.display.category)
        assertEquals(FindingCategory.DEVICE_POSTURE, posture.display.category)
        assertFalse(app.display.suppressFinding)
    }

    @Test
    fun `a suppressed rule may omit display category`() {
        // The atom shape: timeline building blocks that produce no findings.
        val atom = requireNotNull(SigmaRuleParser.parse(rule("suppress_finding: true")))

        assertTrue(atom.display.suppressFinding)
    }

    @Test
    fun `every bundled finding-producing rule declares a display category`() {
        // The on-disk guard: with the default gone, a bundled rule that forgot the
        // field would be dropped at load time on every device. Catch it at build.
        val dir = listOf(
            java.io.File("app/src/main/res/raw"),
            java.io.File("src/main/res/raw"),
            java.io.File("/home/yasir/AndroDR/app/src/main/res/raw"),
        ).firstOrNull { it.isDirectory } ?: error("res/raw not found")

        val offenders = dir.listFiles { f -> f.name.startsWith("sigma_androdr_") && f.name.endsWith(".yml") }!!
            .filterNot { it.name.contains("_corr_") }
            .mapNotNull { f ->
                runCatching { SigmaRuleParser.parse(f.readText()) }
                    .exceptionOrNull()
                    ?.let { "${f.name}: ${it.message}" }
            }

        assertTrue("bundled rules the parser now rejects:\n${offenders.joinToString("\n")}", offenders.isEmpty())
    }
}
