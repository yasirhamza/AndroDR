package com.androdr.scanner

import android.content.Context
import com.androdr.data.model.ScanResult
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleParser
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

/**
 * Gate D1: an imported DNS finding row carries the record's own time.
 *
 * Imported DNS records used to be evaluated without a `timestamp` field, so a
 * DNS finding from an intrusion-log import was persisted at 0 ("Unknown")
 * while connect and security findings carried their event time. Imported DNS
 * is now evaluated through [com.androdr.data.model.ImportedDnsEvent.toFieldMap],
 * which also carries `resolved_ips`.
 */
class DnsFindingTimestampTest {

    private val eventTime = 1_787_400_345_334L

    private val log = """{"dns_event":{"event_id":0,"event_time":$eventTime,"package_name":"com.evil.app",""" +
        """"hostname":"api.badexample.com","ip_addresses":["/34.160.125.113"],"ip_addresses_count":1}}"""

    private fun rule(id: String, field: String, value: String): SigmaRule = SigmaRuleParser.parse(
        """
            title: Test $id
            id: $id
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: dns_monitor
            detection:
                selection:
                    $field: $value
                condition: selection
            level: high
            tags:
                - attack.t1437
            display:
                category: app_risk
        """.trimIndent()
    )!!

    private fun analyze(): IntrusionLogAnalysisResult {
        val engine = SigmaRuleEngine(mockk<Context>(relaxed = true))
        engine.setRemoteRules(
            listOf(
                rule("androdr-d1-domain", "domain", "api.badexample.com"),
                rule("androdr-d1-ip", "resolved_ips", "34.160.125.113"),
            )
        )
        val entries = sequenceOf("2026-08-21.txt" to ByteArrayInputStream(log.toByteArray()))
        return IntrusionLogAnalyzer(mockk(relaxed = true), engine, mockk(relaxed = true))
            .analyzeEntries(entries, uidResolver = { -1 }, capturedAt = 1_787_400_400_000L)
    }

    @Test
    fun `imported dns finding carries the record timestamp`() {
        val finding = analyze().findings.single { it.ruleId == "androdr-d1-domain" && it.triggered }
        assertEquals(eventTime.toString(), finding.matchContext["timestamp"])
    }

    @Test
    fun `imported dns is evaluated with its resolved ips`() {
        assertTrue(analyze().findings.any { it.ruleId == "androdr-d1-ip" && it.triggered })
    }

    @Test
    fun `persisted imported dns finding row has the record time`() {
        val orchestrator = ScanOrchestrator(
            appScanner = mockk(relaxed = true),
            deviceAuditor = mockk(relaxed = true),
            processScanner = mockk(relaxed = true),
            fileArtifactScanner = mockk(relaxed = true),
            accessibilityAuditScanner = mockk(relaxed = true),
            receiverAuditScanner = mockk(relaxed = true),
            appOpsScanner = mockk(relaxed = true),
            usageStatsScanner = mockk(relaxed = true),
            bugReportAnalyzer = mockk(relaxed = true),
            intrusionLogAnalyzer = mockk(relaxed = true),
            scanRepository = mockk(relaxed = true),
            dnsEventDao = mockk(relaxed = true),
            forensicTimelineEventDao = mockk(relaxed = true),
            timelineRows = mockk(relaxed = true),
            installEventEmitter = mockk(relaxed = true),
            deviceAdminGrantEmitter = mockk(relaxed = true),
            sigmaRuleEngine = mockk(relaxed = true),
            sigmaCorrelationEngine = mockk(relaxed = true),
            indicatorResolver = mockk(relaxed = true),
            sigmaRuleFeed = mockk(relaxed = true),
            knownAppResolver = mockk(relaxed = true),
            oemPrefixResolver = mockk(relaxed = true),
            brandImpersonationResolver = mockk(relaxed = true),
            context = mockk(relaxed = true),
        )
        val scan = ScanResult(
            id = 7L, timestamp = 7L, findings = emptyList(), bugReportFindings = emptyList(),
            riskySideloadCount = 0, knownMalwareCount = 0,
        )
        val rows = orchestrator.buildIntrusionLogTimelineEvents(analyze(), scan)
        assertEquals(eventTime, rows.single { it.ruleId == "androdr-d1-domain" }.startTimestamp)
    }
}
