package com.androdr.reporting

import com.androdr.data.model.ScanResult
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReportFormatterTest {

    private fun buildScan(
        appRisks: List<Finding> = emptyList(),
        deviceFlags: List<Finding> = emptyList(),
        knownMalwareCount: Int = 0,
        riskySideloadCount: Int = 0
    ): ScanResult = ScanResult(
        id = 1L,
        timestamp = 1711900800000,
        findings = deviceFlags + appRisks,
        bugReportFindings = emptyList(),
        riskySideloadCount = riskySideloadCount,
        knownMalwareCount = knownMalwareCount
    )

    private val cleanScan = buildScan()

    private val malwareFinding = Finding(
        ruleId = "androdr-001",
        title = "Known Malicious Package",
        level = "critical",
        category = FindingCategory.APP_RISK,
        triggered = true,
        guidance = "UNINSTALL IMMEDIATELY -- matches known malware signatures",
        matchContext = mapOf("package_name" to "com.evil.spy", "app_name" to "EvilSpy"),
        impliesFlags = listOf("known_malware")
    )

    private val sideloadFinding = Finding(
        ruleId = "androdr-010",
        title = "Sideloaded Application",
        level = "high",
        category = FindingCategory.APP_RISK,
        triggered = true,
        guidance = "REVIEW -- sideloaded app with elevated permissions; verify intentional",
        matchContext = mapOf(
            "package_name" to "com.unknown.app",
            "is_sideloaded" to "true"
        ),
        impliesFlags = listOf("sideloaded")
    )

    private val impersonationFinding = Finding(
        ruleId = "androdr-014",
        title = "App Impersonation",
        level = "high",
        category = FindingCategory.APP_RISK,
        triggered = true,
        guidance = "UNINSTALL -- impersonates a legitimate app; likely malicious",
        matchContext = mapOf(
            "package_name" to "org.telegram.messenger",
            "app_name" to "Telegram",
            "is_sideloaded" to "true"
        ),
        impliesFlags = listOf("sideloaded")
    )

    private val deviceFinding = Finding(
        ruleId = "androdr-040",
        title = "USB Debugging Enabled",
        level = "high",
        category = FindingCategory.DEVICE_POSTURE,
        triggered = true,
        remediation = listOf("Disable USB debugging in Developer Options")
    )

    @Test
    fun `verdict shows no threats when clean`() {
        val text = ReportFormatter.formatScanReport(cleanScan, emptyList(), emptyList(), versionName = "test")
        assertTrue(text.contains("No threats detected"))
        assertTrue(text.contains("SUMMARY:"))
        assertTrue(text.contains("Flagged: 0"))
    }

    @Test
    fun `verdict shows device settings when only device issues`() {
        val scan = buildScan(deviceFlags = listOf(deviceFinding))
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        assertTrue(text.contains("device setting(s) need attention"))
        assertTrue(text.contains("Device posture: USB Debugging Enabled"))
    }

    @Test
    fun `action guidance from rule guidance field for malware`() {
        val scan = buildScan(appRisks = listOf(malwareFinding), knownMalwareCount = 1)
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        assertTrue(text.contains("ACTION REQUIRED:"))
        assertTrue("Guidance from rule", text.contains("UNINSTALL IMMEDIATELY"))
    }

    @Test
    fun `action guidance from rule guidance field for sideloads`() {
        val scan = buildScan(appRisks = listOf(sideloadFinding), riskySideloadCount = 1)
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        assertTrue("Guidance from rule", text.contains("REVIEW -- sideloaded app"))
    }

    @Test
    fun `display names resolve in app findings`() {
        val scan = buildScan(appRisks = listOf(sideloadFinding))
        val names = mapOf("com.unknown.app" to "Mystery App")
        val text = ReportFormatter.formatScanReport(
            scan, emptyList(), emptyList(), displayNames = names,
            versionName = "test"
        )
        assertTrue("Display name should appear", text.contains("Mystery App"))
    }

    @Test
    fun `per-app guidance labels present`() {
        val scan = buildScan(
            appRisks = listOf(malwareFinding, sideloadFinding),
            knownMalwareCount = 1,
            riskySideloadCount = 1
        )
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        assertTrue(text.contains("UNINSTALL IMMEDIATELY"))
        assertTrue(text.contains("REVIEW -- sideloaded app"))
    }

    @Test
    fun `output is ASCII only`() {
        val scan = buildScan(
            appRisks = listOf(malwareFinding, sideloadFinding),
            deviceFlags = listOf(deviceFinding),
            knownMalwareCount = 1,
            riskySideloadCount = 1
        )
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        val nonAscii = text.filter { it.code > 127 }
        assertTrue("Non-ASCII characters found: $nonAscii", nonAscii.isEmpty())
    }

    @Test
    fun `no action block when scan is clean`() {
        val text = ReportFormatter.formatScanReport(cleanScan, emptyList(), emptyList(), versionName = "test")
        assertFalse(text.contains("ACTION REQUIRED:"))
    }

    // -- ExportMode tests -----------------------------------------------------

    private fun richScan() = buildScan(
        appRisks = listOf(malwareFinding),
        deviceFlags = listOf(deviceFinding)
    )

    @Test
    fun `BOTH mode contains both section markers`() {
        val text = ReportFormatter.formatScanReport(
            richScan(), emptyList(), listOf("log line"),
            mode = ExportMode.BOTH, versionName = "test"
        )
        assertTrue(text.contains("FINDINGS SECTION"))
        assertTrue(text.contains("TELEMETRY SECTION"))
        assertTrue(text.contains("DNS ACTIVITY"))
        assertTrue(text.contains("DEVICE CHECKS"))
    }

    @Test
    fun `TELEMETRY_ONLY writes only telemetry section`() {
        val text = ReportFormatter.formatScanReport(
            richScan(), emptyList(), listOf("log line"),
            mode = ExportMode.TELEMETRY_ONLY, versionName = "test"
        )
        assertTrue(text.contains("TELEMETRY SECTION"))
        assertTrue(text.contains("DNS ACTIVITY"))
        assertFalse(text.contains("FINDINGS SECTION"))
        assertFalse(text.contains("DEVICE CHECKS"))
        assertFalse(text.contains("APP RISKS"))
        assertFalse(text.contains("OVERALL RISK:"))
    }

    @Test
    fun `FINDINGS_ONLY writes only findings section`() {
        val text = ReportFormatter.formatScanReport(
            richScan(), emptyList(), listOf("log line"),
            mode = ExportMode.FINDINGS_ONLY, versionName = "test"
        )
        assertTrue(text.contains("FINDINGS SECTION"))
        assertTrue(text.contains("DEVICE CHECKS"))
        assertTrue(text.contains("OVERALL RISK:"))
        assertFalse(text.contains("TELEMETRY SECTION"))
        assertFalse(text.contains("DNS ACTIVITY"))
        assertFalse(text.contains("APPLICATION LOG"))
    }

    @Test
    fun `format version line is present`() {
        val text = ReportFormatter.formatScanReport(cleanScan, emptyList(), emptyList(), versionName = "test")
        assertTrue(text.contains("Format    : v${ReportExporter.EXPORT_FORMAT_VERSION}"))
    }

    // -- Flag aggregation tests (issue #205) ----------------------------------

    @Test
    fun `impersonation finding alone renders Sideloaded flag via impliesFlags`() {
        // Issue #205: FakeTelegram (org.telegram.messenger spoof) fires
        // androdr-014 but NOT androdr-010, because the sideload rule's
        // filter_known_good suppresses it for known-popular package names.
        // The Sideloaded flag must still surface from the impersonation
        // rule's own implies_flags declaration.
        val scan = buildScan(appRisks = listOf(impersonationFinding))
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        assertTrue("Flags line should appear", text.contains("Flags   :"))
        assertTrue("Sideloaded flag must render", text.contains("Flags   : Sideloaded"))
    }

    @Test
    fun `sideload and impersonation findings both fire — Sideloaded flag not duplicated`() {
        val both = listOf(sideloadFinding, impersonationFinding.copy(
            matchContext = impersonationFinding.matchContext + ("package_name" to "com.unknown.app")
        ))
        val scan = buildScan(appRisks = both)
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        val flagsLine = text.lineSequence().first { it.trimStart().startsWith("Flags   :") }
        assertEquals("Flags   : Sideloaded", flagsLine.trim())
    }

    @Test
    fun `known malware finding renders Known Malware flag via impliesFlags`() {
        val scan = buildScan(appRisks = listOf(malwareFinding), knownMalwareCount = 1)
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        assertTrue("Known Malware flag must render",
            text.contains("Flags   : [!] Known Malware"))
    }

    @Test
    fun `malware plus sideload renders both flags`() {
        val both = listOf(malwareFinding.copy(
            matchContext = mapOf("package_name" to "com.unknown.app")
        ), sideloadFinding)
        val scan = buildScan(appRisks = both, knownMalwareCount = 1, riskySideloadCount = 1)
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        assertTrue("Both flags must render",
            text.contains("Flags   : [!] Known Malware / Sideloaded"))
    }

    @Test
    fun `finding with no impliesFlags produces no Flags line`() {
        val orphan = Finding(
            ruleId = "androdr-999",
            title = "Some Other Finding",
            level = "medium",
            category = FindingCategory.APP_RISK,
            triggered = true,
            matchContext = mapOf("package_name" to "com.orphan.app")
            // impliesFlags defaults to empty
        )
        val scan = buildScan(appRisks = listOf(orphan))
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        assertFalse("No Flags line expected when no implies_flags", text.contains("Flags   :"))
    }
}
