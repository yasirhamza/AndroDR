package com.androdr.sigma

import com.androdr.data.model.DnsEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsEvaluationTest {

    @Test
    fun `toFieldMap exposes domain and source_package`() {
        val event = DnsEvent(
            id = 1, timestamp = 0L, domain = "api.flexispy.com",
            appUid = 10042, appName = "com.vvt.android.syncmanager",
            isBlocked = false, reason = null
        )
        val fields = event.toFieldMap()

        assertEquals("api.flexispy.com", fields["domain"])
        assertEquals("com.vvt.android.syncmanager", fields["source_package"])
        assertEquals(10042, fields["app_uid"])
        assertEquals(false, fields["is_blocked"])
    }

    @Test
    fun `dns_monitor rule fires on stalkerware C2 domain`() {
        val ruleYaml = """
            title: Stalkerware C2 domain
            id: androdr-055
            status: experimental
            description: Test
            logsource:
                product: androdr
                service: dns_monitor
            detection:
                selection:
                    domain|contains:
                        - flexispy.com
                        - thetruthspy.com
                condition: selection
            level: high
            tags:
                - attack.t1437
        """.trimIndent()

        val rule = SigmaRuleParser.parse(ruleYaml)!!
        val maliciousRecord = mapOf<String, Any?>(
            "domain" to "api.flexispy.com",
            "source_package" to "com.vvt.android.syncmanager"
        )
        val benignRecord = mapOf<String, Any?>(
            "domain" to "google.com",
            "source_package" to "com.google.android.gms"
        )

        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(maliciousRecord), "dns_monitor", emptyMap(), emptyMap()
        )
        assertTrue("Should fire on flexispy.com", findings.any { it.triggered })

        val benignFindings = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(benignRecord), "dns_monitor", emptyMap(), emptyMap()
        )
        assertTrue("Should not fire on google.com", benignFindings.none { it.triggered })
    }

    @Test
    fun `dns_monitor rule does not fire for wrong service`() {
        val ruleYaml = """
            title: Stalkerware C2 domain
            id: androdr-055
            status: experimental
            description: Test
            logsource:
                product: androdr
                service: dns_monitor
            detection:
                selection:
                    domain|contains:
                        - flexispy.com
                condition: selection
            level: high
            tags:
                - attack.t1437
        """.trimIndent()

        val rule = SigmaRuleParser.parse(ruleYaml)!!
        val record = mapOf<String, Any?>("domain" to "api.flexispy.com")

        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(record), "app_scanner", emptyMap(), emptyMap()
        )
        assertEquals("dns_monitor rule should not fire for app_scanner service", 0, findings.size)
    }
}
