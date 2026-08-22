package com.androdr.ui.timeline

import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression guard for #342 C2 (correctness C#5 / architect #5).
 *
 * The imported adapters used to stamp dns:/net:/sec: correlation ids on every
 * raw row. TimelineClusters Pass-2 clusters any >= 2 rows sharing an
 * effectiveCorrelationId, so N identical imported events (N keyguard_dismissed
 * security events sharing sec:$tag, a domain resolved twice sharing dns:<domain>)
 * formed one meaningless PRE_LINKED cluster. The fix stops stamping raw rows.
 *
 * This test drives clustering the same way the Timeline UI does
 * ([partitionSignals]) and also asserts the tighter invariant directly: no
 * imported raw row carries a non-empty correlationId. Either check fails if the
 * unconditional stamping is reintroduced.
 */
class IntrusionLogClusterRegressionTest {

    private fun securityRow(id: Long) = SecurityLogEvent(
        // Same tag => same old sec:$tag key; empty packageName => no pkg: grouping,
        // so the ONLY thing that could cluster these is a stamped correlationId.
        timestamp = 1_700_000_000_000L + id, tag = 210_012, tagName = "keyguard_dismissed",
        securityData = emptyList(), source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
    ).toForensicTimelineEvent(scanResultId = 1L).copy(id = id)

    private fun dnsRow(id: Long) = ImportedDnsEvent(
        event = DnsEvent(
            timestamp = 1_700_000_000_000L + id, domain = "cdn.example.com", appUid = -1,
            appName = null, isBlocked = false, reason = null,
        ),
        resolvedIps = listOf("1.1.1.1"),
    ).toForensicTimelineEvent(scanResultId = 1L).copy(id = id)

    private fun connectRow(id: Long) = NetworkTelemetry(
        destinationIp = "8.8.8.8", destinationPort = 853, protocol = null,
        appUid = -1, appName = null, timestamp = 1_700_000_000_000L + id,
        source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
    ).toForensicTimelineEvent(scanResultId = 1L).copy(id = id)

    @Test
    fun `identical imported rows do not form a PRE_LINKED cluster`() {
        val rows: List<ForensicTimelineEvent> =
            (1L..400L).map { securityRow(it) } +
                (401L..410L).map { dnsRow(it) } +
                (411L..420L).map { connectRow(it) }

        val (clusters, standalone) = partitionSignals(rows)

        assertTrue(
            "Imported raw rows must not form a PRE_LINKED cluster (unconditional " +
                "correlation-id stamping reintroduced?), got: " +
                clusters.map { it.pattern to it.events.size },
            clusters.none { it.pattern == CorrelationPattern.PRE_LINKED },
        )
        // Every imported row should render standalone.
        assertTrue(
            "Expected all ${rows.size} rows standalone, got ${standalone.size}",
            standalone.size == rows.size,
        )
    }

    @Test
    fun `no imported raw row carries a non-empty correlation id`() {
        val rows = listOf(securityRow(1L), dnsRow(2L), connectRow(3L))
        assertTrue(
            "Imported raw rows must carry an empty correlationId (C2; join deferred " +
                "to #352). Offenders: " + rows.filter { it.correlationId.isNotEmpty() }
                .map { it.category to it.correlationId },
            rows.all { it.correlationId.isEmpty() },
        )
    }
}
