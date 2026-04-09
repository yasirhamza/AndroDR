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
        assertEquals("HIGH", event.severity)
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
        assertEquals("INFO", event.severity)
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
        assertEquals("HIGH", event.severity)
        assertEquals("androdr-060", event.ruleId)
        assertEquals(5000L, event.scanResultId)
        assertEquals("com.evil.spy", event.packageName)
        assertEquals("t1626", event.attackTechniqueId)
        assertTrue(event.telemetrySource == TelemetrySource.LIVE_SCAN)
    }

    @Test
    fun `bugreport TimelineEvent maps to forensic event`() {
        val legacy = com.androdr.data.model.TimelineEvent(
            timestamp = 4000L, source = "appops",
            category = "permission_use",
            description = "com.spy used CAMERA at 14:30",
            severity = "MEDIUM"
        )
        val event = legacy.toForensicTimelineEvent(scanResultId = 9000L)
        assertEquals("appops", event.source)
        assertEquals("permission_use", event.category)
        assertEquals(9000L, event.scanResultId)
        assertTrue(event.telemetrySource == TelemetrySource.BUGREPORT_IMPORT)
    }
}
