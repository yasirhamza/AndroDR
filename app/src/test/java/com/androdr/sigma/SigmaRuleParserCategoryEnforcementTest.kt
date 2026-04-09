// app/src/test/java/com/androdr/sigma/SigmaRuleParserCategoryEnforcementTest.kt
package com.androdr.sigma

import org.junit.Assert.fail
import org.junit.Test

class SigmaRuleParserCategoryEnforcementTest {

    /** A syntactically valid rule that omits the top-level `category:` field. */
    private val yamlMissingCategory = """
        title: Missing category rule
        id: test-cat-missing
        status: experimental
        logsource:
            product: androdr
            service: app_scanner
        detection:
            selection:
                is_sideloaded: true
            condition: selection
        level: medium
    """.trimIndent()

    /** A syntactically valid rule with a `category:` value that is not in the allowed set. */
    private val yamlInvalidCategory = """
        title: Invalid category rule
        id: test-cat-invalid
        status: experimental
        category: bogus_value
        logsource:
            product: androdr
            service: app_scanner
        detection:
            selection:
                is_sideloaded: true
            condition: selection
        level: medium
    """.trimIndent()

    @Test
    fun `parse throws SigmaRuleParseException when category field is absent`() {
        try {
            SigmaRuleParser.parse(yamlMissingCategory)
            fail("Expected SigmaRuleParseException but no exception was thrown")
        } catch (e: SigmaRuleParseException) {
            // expected — pass
        }
    }

    @Test
    fun `parse throws SigmaRuleParseException when category has an invalid value`() {
        try {
            SigmaRuleParser.parse(yamlInvalidCategory)
            fail("Expected SigmaRuleParseException but no exception was thrown")
        } catch (e: SigmaRuleParseException) {
            // expected — pass
        }
    }
}
