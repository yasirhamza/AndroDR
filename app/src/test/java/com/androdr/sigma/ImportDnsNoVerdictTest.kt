package com.androdr.sigma

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ImportedDnsEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * R22: an imported DNS record carries no tunnel verdict. AndroDR was not in the path, so
 * `is_blocked` / `reason` (the tunnel's defaults) would be fabricated facts. Emitters emit facts.
 */
class ImportDnsNoVerdictTest {

    private val event = DnsEvent(
        timestamp = 5L, domain = "c2.example", appUid = 10_001, appName = "com.a",
        isBlocked = false, reason = null,
    )

    private fun importedFields(): Map<String, Any?> =
        IntrusionLogRecordBuilders.importedDns(listOf(ImportedDnsEvent(event, listOf("1.2.3.4")))).single().fields

    @Test
    fun `an imported DNS record has no is_blocked and no reason key`() {
        val fields = importedFields()
        assertFalse(fields.toString(), fields.containsKey("is_blocked"))
        assertFalse(fields.toString(), fields.containsKey("reason"))
        assertEquals("c2.example", fields["domain"])
        assertEquals(listOf("1.2.3.4"), fields["resolved_ips"])
        assertEquals(5L, fields["timestamp"])
        assertEquals("com.a", fields["source_package"])
        assertEquals(10_001, fields["app_uid"])
    }

    @Test
    fun `a live tunnel record still carries both`() {
        val live = LiveRecordBuilders.dns(listOf(event.copy(isBlocked = true, reason = "blocklist"))).single().fields
        assertEquals(true, live["is_blocked"])
        assertEquals("blocklist", live["reason"])
        val liveDefault = LiveRecordBuilders.dns(listOf(event)).single().fields
        assertTrue(liveDefault.containsKey("is_blocked"))
        assertTrue(liveDefault.containsKey("reason"))
        assertEquals(false, liveDefault["is_blocked"])
        assertEquals(null, liveDefault["reason"])
    }

    @Test
    fun `a rule selecting is_blocked true never matches an import`() {
        val rule = SigmaRuleParser.parse(
            """
            title: Blocked DNS
            id: test-blocked
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: dns_monitor
            detection:
                selection:
                    is_blocked: true
                condition: selection
            level: high
            display:
                category: app_risk
            """.trimIndent()
        )!!
        val imported = importedFields()
        val importedHits =
            SigmaRuleEvaluator.evaluate(listOf(rule), listOf(imported), "dns_monitor", emptyMap(), emptyMap())
        assertTrue(importedHits.none { it.triggered })
        val live = LiveRecordBuilders.dns(listOf(event.copy(isBlocked = true, reason = "blocklist"))).single().fields
        val liveHits = SigmaRuleEvaluator.evaluate(listOf(rule), listOf(live), "dns_monitor", emptyMap(), emptyMap())
        assertTrue(liveHits.any { it.triggered })
    }
}
