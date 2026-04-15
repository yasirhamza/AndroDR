// app/src/test/java/com/androdr/sigma/SigmaRuleParserTest.kt
package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SigmaRuleParserTest {

    @Test
    fun `parses basic SIGMA rule`() {
        val yaml = """
            title: Test rule
            id: test-001
            status: production
            category: incident
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
            category: incident
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
            category: incident
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
    fun `parses display block`() {
        val yaml = """
            title: USB Debugging enabled
            id: test-display
            category: device_posture
            logsource:
                product: androdr
                service: device_auditor
            detection:
                selection:
                    adb_enabled: true
                condition: selection
            level: high
            display:
                category: device_posture
                icon: usb
                triggered_title: "USB Debugging Enabled"
                safe_title: "USB Debugging Disabled"
                evidence_type: none
                summary_template: ""
            remediation:
                - "Disable USB Debugging"
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        assertEquals("device_posture", rule!!.display.category)
        assertEquals("usb", rule.display.icon)
        assertEquals("USB Debugging Enabled", rule.display.triggeredTitle)
        assertEquals("USB Debugging Disabled", rule.display.safeTitle)
        assertEquals("none", rule.display.evidenceType)
    }

    @Test
    fun `display block is optional`() {
        val yaml = """
            title: No display
            id: test-no-display
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    is_sideloaded: true
                condition: selection
            level: medium
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        assertEquals("device_posture", rule!!.display.category)
        assertEquals("none", rule.display.evidenceType)
        assertEquals("", rule.display.triggeredTitle)
    }

    @Test
    fun `parses campaign tags from tags list`() {
        val yaml = """
            title: Campaign rule
            id: test-campaign
            category: device_posture
            logsource:
                product: androdr
                service: device_auditor
            detection:
                selection:
                    unpatched_cve_count|gte: 1
                condition: selection
            level: critical
            tags:
                - attack.t1404
                - campaign.pegasus
                - campaign.predator
        """.trimIndent()

        val rule = SigmaRuleParser.parse(yaml)
        assertNotNull(rule)
        val campaigns = rule!!.tags.filter { it.startsWith("campaign.") }
        assertEquals(2, campaigns.size)
        assertEquals("campaign.pegasus", campaigns[0])
    }

    @Test
    fun `unknown modifier throws SigmaRuleParseException, not silent EQUALS fallback`() {
        val yaml = """
            title: Unknown modifier rule
            id: test-unknown-modifier
            category: incident
            logsource:
                product: androdr
                service: app_scanner
            detection:
                selection:
                    permissions|contains_all:
                        - android.permission.READ_SMS
                        - android.permission.SEND_SMS
                condition: selection
            level: medium
        """.trimIndent()

        val ex = assertThrows(SigmaRuleParseException::class.java) {
            SigmaRuleParser.parse(yaml)
        }
        assertTrue(
            "Exception message should name the unknown modifier. Got: ${ex.message}",
            ex.message!!.contains("Unknown modifier") && ex.message!!.contains("contains_all")
        )
    }

    @Test
    fun `parses tags and falsepositives`() {
        val yaml = """
            title: Tagged rule
            id: test-004
            category: incident
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
