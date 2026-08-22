package com.androdr.reporting

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IntrusionLogReportSectionTest {

    private fun scan() = ScanResult(
        id = 1L, timestamp = 1787400345334L, findings = emptyList(),
        bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0
    )

    private fun row(category: String, description: String, pkg: String) = ForensicTimelineEvent(
        startTimestamp = 1787400345540L, source = "intrusion_log", category = category,
        description = description, packageName = pkg,
        telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT
    )

    @Test
    fun `intrusion events render a section with category, description and attribution`() {
        val text = ReportFormatter.formatScanReport(
            scan(), dnsEvents = emptyList(), logLines = emptyList(),
            intrusionEvents = listOf(
                row("network_connect", "Connect: 8.8.8.8:853", "com.samsung.wearable.watchuniteplugin"),
                row("security_event", "Security: adb_shell_cmd", "")
            ),
            versionName = "test"
        )
        assertTrue(text.contains("INTRUSION LOG"))
        assertTrue(text.contains("Connect: 8.8.8.8:853"))
        assertTrue(text.contains("com.samsung.wearable.watchuniteplugin"))
        assertTrue(text.contains("Security: adb_shell_cmd"))
    }

    @Test
    fun `no intrusion events - no section`() {
        val text = ReportFormatter.formatScanReport(
            scan(), dnsEvents = emptyList(), logLines = emptyList(), versionName = "test"
        )
        assertFalse(text.contains("INTRUSION LOG"))
    }

    @Test
    fun `findings-only mode omits the intrusion section`() {
        val text = ReportFormatter.formatScanReport(
            scan(), dnsEvents = emptyList(), logLines = emptyList(),
            mode = ExportMode.FINDINGS_ONLY,
            intrusionEvents = listOf(row("network_connect", "Connect: 1.2.3.4:80", "com.a")),
            versionName = "test"
        )
        assertFalse(text.contains("INTRUSION LOG"))
    }
}
