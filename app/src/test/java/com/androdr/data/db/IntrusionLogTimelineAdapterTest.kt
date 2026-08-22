package com.androdr.data.db

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.ImportedDnsEvent
import org.junit.Assert.assertEquals
import org.junit.Test

class IntrusionLogTimelineAdapterTest {

    // #342 C2: all three imported RAW adapters MUST leave correlationId empty.
    // The prior design stamped dns:/net:/sec: ids unconditionally, which
    // TimelineClusters Pass-2 then collapsed into meaningless type/domain-level
    // PRE_LINKED clusters (see IntrusionLogClusterRegressionTest). These
    // assertions are the tight guard against reintroducing that stamping; the
    // finding↔raw-evidence join is deferred to #352.

    @Test
    fun `imported dns event maps with no correlation id`() {
        val row = ImportedDnsEvent(
            event = DnsEvent(
                timestamp = 5L, domain = "h.example.com", appUid = 100,
                appName = "com.a", isBlocked = false, reason = null
            ),
            resolvedIps = listOf("1.1.1.1", "2.2.2.2")
        ).toForensicTimelineEvent(scanResultId = 9L)
        assertEquals("intrusion_log", row.source)
        assertEquals("dns_query", row.category)
        assertEquals("", row.correlationId) // C2: raw-row join deferred to #352
        assertEquals("resolved: 1.1.1.1, 2.2.2.2", row.details)
        assertEquals(TelemetrySource.INTRUSION_LOG_IMPORT, row.telemetrySource)
        assertEquals(9L, row.scanResultId)
        assertEquals(5L, row.startTimestamp)
    }

    @Test
    fun `connect event maps to network_connect with no correlation id`() {
        val row = NetworkTelemetry(
            destinationIp = "1.2.3.4", destinationPort = 853, protocol = null,
            appUid = -1, appName = "com.b", timestamp = 7L,
            source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L
        ).toForensicTimelineEvent(scanResultId = 9L)
        assertEquals("intrusion_log", row.source)
        assertEquals("network_connect", row.category)
        assertEquals("", row.correlationId) // C2: raw-row join deferred to #352
        assertEquals("com.b", row.packageName)
        assertEquals(7L, row.startTimestamp)
    }

    @Test
    fun `security event maps to security_event with no correlation id`() {
        val row = SecurityLogEvent(
            timestamp = 3L, tag = 210002, tagName = "adb_shell_cmd",
            securityData = listOf("id"), source = TelemetrySource.INTRUSION_LOG_IMPORT,
            capturedAt = 0L
        ).toForensicTimelineEvent(scanResultId = 9L)
        assertEquals("intrusion_log", row.source)
        assertEquals("security_event", row.category)
        assertEquals("", row.correlationId) // C2: raw-row join deferred to #352
        assertEquals("Security: adb_shell_cmd", row.description)
        assertEquals("id", row.details)
    }
}
