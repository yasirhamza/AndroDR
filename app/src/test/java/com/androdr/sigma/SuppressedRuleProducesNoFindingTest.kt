package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * `display.suppress_finding: true` must be honoured by the evaluator, not merely
 * tolerated by the parser. Before #367 nothing read the field: the five timeline
 * atoms stayed out of the findings list only because no code path happened to feed
 * `timeline`-service records to the evaluator. Had one been added, every atom would
 * have surfaced as an informational "device setting" via the old category default.
 */
class SuppressedRuleProducesNoFindingTest {

    private fun rule(display: String) = """
        title: Suppression probe
        id: test-suppress
        status: experimental
        category: incident
        logsource:
            product: androdr
            service: app_scanner
        detection:
            selection:
                is_sideloaded: true
            condition: selection
        level: informational
        display:
            $display
    """.trimIndent()

    private val matchingRecord: List<Map<String, Any?>> = listOf(mapOf("is_sideloaded" to true))

    @Test
    fun `a suppressed rule yields no finding even when its selection matches`() {
        val atom = requireNotNull(SigmaRuleParser.parse(rule("suppress_finding: true")))

        val findings = SigmaRuleEvaluator.evaluate(listOf(atom), matchingRecord, "app_scanner")

        assertEquals("suppressed rule must produce nothing", 0, findings.size)
    }

    @Test
    fun `the same rule unsuppressed yields exactly one finding`() {
        // The control: proves the selection really matches, so the test above
        // passes for the right reason.
        val visible = requireNotNull(SigmaRuleParser.parse(rule("category: app_risk")))

        val findings = SigmaRuleEvaluator.evaluate(listOf(visible), matchingRecord, "app_scanner")

        assertEquals(1, findings.size)
        assertEquals(FindingCategory.APP_RISK, findings.single().category)
    }
}
