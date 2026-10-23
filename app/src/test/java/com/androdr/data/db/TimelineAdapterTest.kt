package com.androdr.data.db

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TimelineAdapterTest {

    @Test
    fun `DnsEvent with IOC match maps to HIGH timeline event`() {
        val dns = DnsEvent(
            id = 1, timestamp = 1000L, domain = "evil.com",
            appUid = 10100, appName = "SuspectApp",
            isBlocked = true, reason = "IOC: Pegasus C2"
        )
        val event = dns.toForensicTimelineEvent()
        assertEquals("dns_monitor", event.source)
        assertEquals("ioc_match", event.category)
        assertEquals("evil.com", event.iocIndicator)
        assertEquals("domain", event.iocType)
        assertTrue(event.telemetrySource == TelemetrySource.LIVE_SCAN)
    }

    @Test
    fun `DnsEvent without match maps to INFO timeline event`() {
        val dns = DnsEvent(
            id = 2, timestamp = 2000L, domain = "google.com",
            appUid = 10200, appName = "Chrome",
            isBlocked = false, reason = null
        )
        val event = dns.toForensicTimelineEvent()
        assertEquals("", event.iocIndicator)
    }

    @Test
    fun `Finding maps to timeline event with rule and scan context`() {
        val finding = Finding(
            ruleId = "androdr-060",
            title = "Active Accessibility Service",
            description = "com.evil.spy has accessibility enabled",
            level = "high",
            category = FindingCategory.APP_RISK,
            tags = listOf("attack.t1626"),
            matchContext = mapOf("package_name" to "com.evil.spy")
        )
        val scanResult = ScanResult(
            id = 5000L, timestamp = 3000L,
            findings = listOf(finding),
            bugReportFindings = emptyList(),
            riskySideloadCount = 0, knownMalwareCount = 0
        )
        val event = finding.toForensicTimelineEvent(scanResult)
        assertEquals("app_scanner", event.source)
        assertEquals("app_risk", event.category)
        assertEquals("androdr-060", event.ruleId)
        assertEquals(5000L, event.scanResultId)
        assertEquals("com.evil.spy", event.packageName)
        assertEquals("t1626", event.attackTechniqueId)
        assertTrue(event.telemetrySource == TelemetrySource.LIVE_SCAN)
    }

    private fun iocFindingWith(family: String, tags: List<String> = emptyList()) = Finding(
        ruleId = "androdr-003", title = "Malicious Domain", level = "critical",
        category = FindingCategory.APP_RISK, tags = tags,
        evidence = com.androdr.sigma.Evidence.IocMatch(
            matchedIndicator = "x.example", iocType = "domain", source = "src", family = family,
        ),
        matchContext = mapOf("domain" to "x.example"),
    )

    private val timelineScan = ScanResult(
        id = 1L, timestamp = 1L, findings = emptyList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0,
    )

    @Test
    fun `IocMatch family becomes the timeline campaign name`() {
        val event = iocFindingWith("NoviSpy", tags = listOf("campaign.pegasus"))
            .toForensicTimelineEvent(timelineScan)
        assertEquals("NoviSpy", event.campaignName)
    }

    @Test
    fun `without a family the campaign tag is the campaign name`() {
        val event = iocFindingWith("", tags = listOf("campaign.pegasus"))
            .toForensicTimelineEvent(timelineScan)
        assertEquals("Pegasus", event.campaignName)
    }
}
