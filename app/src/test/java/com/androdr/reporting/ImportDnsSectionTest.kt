package com.androdr.reporting

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A section means one thing.
 *
 * The DNS section was always built from the live tunnel's most recent events, even
 * on the report for an imported log. The result: a report whose findings, summary
 * and coverage line describe an import, above five hundred DNS rows captured by the
 * phone at some unrelated moment (#375). Imported DNS rows existed all along, with
 * their app attribution, on the Timeline.
 *
 * Same principle as #364 and #367: the header has to describe what is underneath it.
 */
class ImportDnsSectionTest {

    private fun scan(source: TelemetrySource) = ScanResult(
        id = 1L, timestamp = 1711900800000, findings = emptyList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = emptyList(), source = source,
    )

    private val liveTunnelRow = DnsEvent(
        timestamp = 1711900800000, domain = "live-tunnel-only.example",
        appUid = 10042, appName = "com.android.chrome", isBlocked = false, reason = null,
    )

    private val importedRow = ForensicTimelineEvent(
        startTimestamp = 1709000000000, source = "intrusion_log", category = "dns_query",
        description = "DNS: imported-only.example", packageName = "com.microsoft.teams",
        processUid = 10099, scanResultId = 1L, telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT,
    )

    private fun report(
        scan: ScanResult,
        dns: List<DnsEvent> = listOf(liveTunnelRow),
        imported: List<ForensicTimelineEvent> = emptyList(),
    ) = ReportFormatter.formatScanReport(
        scan, dns, emptyList(), versionName = "test", mode = ExportMode.TELEMETRY_ONLY,
        intrusionEvents = imported,
    )

    @Test
    fun `an import never shows the live tunnel's DNS`() {
        val text = report(scan(TelemetrySource.INTRUSION_LOG_IMPORT), imported = listOf(importedRow))

        assertFalse(
            "the phone's own tunnel log belongs to a different scan",
            text.contains("live-tunnel-only.example"),
        )
    }

    @Test
    fun `an import shows its own DNS, attributed to the app that made the query`() {
        val text = report(scan(TelemetrySource.INTRUSION_LOG_IMPORT), imported = listOf(importedRow))

        assertTrue(text.contains("imported-only.example"))
        assertTrue("attribution already on the row must survive", text.contains("com.microsoft.teams"))
    }

    @Test
    fun `an import with no DNS of its own says where to look, and still hides the tunnel`() {
        val text = report(scan(TelemetrySource.BUGREPORT_IMPORT))

        assertFalse(text.contains("live-tunnel-only.example"))
        assertTrue("the reader must be told this scan carries no DNS log", text.contains("Timeline"))
    }

    @Test
    fun `a live scan still shows the tunnel it captured`() {
        val text = report(scan(TelemetrySource.LIVE_SCAN))

        assertTrue(text.contains("live-tunnel-only.example"))
        assertTrue(text.contains("com.android.chrome"))
    }

    @Test
    fun `imported rows that matched a threat list are marked as matches`() {
        val matched = importedRow.copy(
            category = "ioc_match",
            description = "DNS: bad.example [MATCHED: blocklist]",
            iocIndicator = "bad.example",
        )

        val text = report(scan(TelemetrySource.INTRUSION_LOG_IMPORT), imported = listOf(matched))

        assertTrue(text.contains("bad.example"))
        assertTrue(text.contains("MATCHED"))
    }
}
