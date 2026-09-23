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

    /**
     * Only the DNS ACTIVITY section. The INTRUSION LOG section below it prints the
     * same rows in another form, so an unscoped `contains` passes even when the DNS
     * branch does nothing at all.
     */
    private fun dnsBlock(text: String) =
        text.substringAfter("DNS ACTIVITY").substringBefore("INTRUSION LOG")

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
        val block = dnsBlock(report(scan(TelemetrySource.INTRUSION_LOG_IMPORT), imported = listOf(importedRow)))

        assertTrue(block.contains("imported-only.example"))
        assertTrue("attribution already on the row must survive", block.contains("com.microsoft.teams"))
    }

    @Test
    fun `an import with no DNS rows in the report says so without claiming the import had none`() {
        // The sheet in History renders reports without embedding imported rows; the
        // wording must not turn "not included here" into "the import carried none".
        val block = dnsBlock(report(scan(TelemetrySource.BUGREPORT_IMPORT)))

        assertFalse(block.contains("live-tunnel-only.example"))
        assertTrue("points at where the import's log lives", block.contains("Timeline"))
        assertTrue("scoped to this report, not to the import", block.contains("included in this report"))
    }

    @Test
    fun `a live scan still shows the tunnel it captured`() {
        val text = report(scan(TelemetrySource.LIVE_SCAN))

        assertTrue(text.contains("live-tunnel-only.example"))
        assertTrue(text.contains("com.android.chrome"))
    }

    @Test
    fun `an imported row is never stamped as allowed`() {
        // The import parser records no block decision, so every imported row would
        // read [ALLOWED] -- including a domain the same report's FINDINGS section
        // names as C2. An import's DNS section states the queries, nothing more.
        val block = dnsBlock(report(scan(TelemetrySource.INTRUSION_LOG_IMPORT), imported = listOf(importedRow)))

        assertFalse("no verdict the data cannot support: $block", block.contains("[ALLOWED]"))
        assertFalse(block.contains("[MATCHED]"))
        assertFalse("nor a matched count", block.contains("matched"))
    }

    @Test
    fun `an import's DNS section claims a sample, never a total`() {
        val rows = (1..600).map { importedRow.copy(description = "DNS: row-$it.example") }

        val block = dnsBlock(report(scan(TelemetrySource.INTRUSION_LOG_IMPORT), imported = rows))

        assertTrue("rows are capped", block.contains("more row(s) not shown"))
        assertTrue("and the cap is honest about what it is", block.contains("not the import's whole log"))
        assertFalse("the last row beyond the cap is absent", block.contains("row-600.example"))
    }

    @Test
    fun `a matched domain is shown by its indicator, not buried in a description`() {
        val matched = importedRow.copy(
            description = "DNS: bad.example [Pegasus]",
            iocIndicator = "bad.example",
        )

        val block = dnsBlock(report(scan(TelemetrySource.INTRUSION_LOG_IMPORT), imported = listOf(matched)))

        assertTrue(block.contains("bad.example"))
        assertFalse("campaign tags belong to FINDINGS, not the domain column", block.contains("[Pegasus]"))
    }
}
