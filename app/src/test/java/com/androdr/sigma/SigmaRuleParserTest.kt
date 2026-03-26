// app/src/test/java/com/androdr/sigma/SigmaRuleParserTest.kt
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class SigmaRuleParserTest {

    @Test
    fun `parses basic SIGMA rule`() {
        val yaml = """
            title: Test rule
            id: test-001
            status: production
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    is_sideloaded: true
                condition: selection
            level: medium
            remediation:
                - "Uninstall the app"
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        assertEquals("test-001", rule!!.id)
        assertEquals("androdr", rule.product)
        assertEquals("app_scanner", rule.service)
        assertEquals("medium", rule.level)
        assertEquals(1, rule.detection.selections.size)
        assertEquals(1, rule.remediation.size)
    }

    @Test
    fun `parses field modifiers`() {
        val yaml = """
            title: Name contains System
            id: test-002
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    app_name|contains:
                        - System
                        - Google
                condition: selection
            level: high
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        val matcher = rule!!.detection.selections["selection"]!!.fieldMatchers[0]
        assertEquals("app_name", matcher.fieldName)
        assertEquals(SigmaModifier.CONTAINS, matcher.modifier)
        assertEquals(2, matcher.values.size)
    }

    @Test
    fun `parses compound condition`() {
        val yaml = """
            title: Compound test
            id: test-003
            logsource:
                product: androdr
                service: app_scanner
            detection:
                sel_untrusted:
                    from_trusted_store: false
                sel_name:
                    app_name|contains: System
                condition: sel_untrusted and sel_name
            level: high
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        assertEquals(2, rule!!.detection.selections.size)
        assertEquals("sel_untrusted and sel_name", rule.detection.condition)
    }

    @Test
    fun `returns null for invalid YAML`() {
        val rule = SigmaRuleParser.parse("not: valid: yaml: [[[")
        assertNull(rule)
    }

    @Test
    fun `parses tags and falsepositives`() {
        val yaml = """
            title: Tagged rule
            id: test-004
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    is_sideloaded: true
                condition: selection
            level: medium
            tags:
                - attack.t1036
                - attack.t1418
            falsepositives:
                - Developer tools
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        assertEquals(2, rule!!.tags.size)
        assertEquals("attack.t1036", rule.tags[0])
        assertEquals(1, rule.falsepositives.size)
    }
}
