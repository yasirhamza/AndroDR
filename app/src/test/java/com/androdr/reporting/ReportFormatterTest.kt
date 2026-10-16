package com.androdr.reporting

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.UNREGISTERED_IOC_LOOKUP
import com.androdr.ioc.Campaign
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
        riskySideloadCount: Int = 0,
        scannerErrors: List<ScannerFailure> = emptyList()
    ): ScanResult = ScanResult(
        id = 1L,
        timestamp = 1711900800000,
        findings = deviceFlags + appRisks,
        bugReportFindings = emptyList(),
        riskySideloadCount = riskySideloadCount,
        knownMalwareCount = knownMalwareCount,
        scannerErrors = scannerErrors
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

    // -- Rule capability skips (#136 R1, Task 2) -------------------------------

    private val capabilitySkip = ScannerFailure(
        scanner = "ruleCapability",
        exception = UNREGISTERED_IOC_LOOKUP,
        message = "rule androdr-010 not evaluated on this build: unregistered ioc_lookup 'trusted_installer_db'"
    )

    private val realScannerFailure = ScannerFailure(
        scanner = "appScanner",
        exception = "IllegalStateException",
        message = "boom"
    )

    @Test
    fun `capability skip renders its own section, not a partial-scan alarm`() {
        val scan = buildScan(scannerErrors = listOf(capabilitySkip))
        val text = ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
        assertTrue(
            // Was "RULES NOT EVALUATED ON THIS BUILD": one reason had a section of its
            // own. Two more reasons existed and were silent (#366, #370), so all three
            // now share one section, grouped by reason.
            "The not-checked section and this reason's heading must appear",
            text.contains(ReportFormatter.NOT_CHECKED_SECTION) &&
                text.contains(NotEvaluatedReason.MISSING_CAPABILITY.heading)
        )
        assertTrue(
            "Capability skip message must appear",
            text.contains(
                "rule androdr-010 not evaluated on this build: " +
                    "unregistered ioc_lookup 'trusted_installer_db'"
            )
        )
        assertFalse("Capability skip must not mark the scan partial", scan.isPartialScan)
    }

    @Test
    fun `real scanner failure marks the scan partial`() {
        val scan = buildScan(scannerErrors = listOf(realScannerFailure))
        assertTrue("A real scanner failure must mark the scan partial", scan.isPartialScan)
    }

    @Test
    fun `no capability skip section when there are no skips`() {
        val text = ReportFormatter.formatScanReport(cleanScan, emptyList(), emptyList(), versionName = "test")
        assertFalse(text.contains(ReportFormatter.NOT_CHECKED_SECTION))
    }

    // -- IOC attribution (B6) --------------------------------------------------

    private fun iocFinding(
        domain: String,
        family: String,
        category: String,
        isBlocked: String,
        reason: String = "IOC_detect: $domain",
        campaign: String = "",
        observedAt: Long = 1711900800000,
        iocType: String = "domain",
        ruleId: String = "androdr-003",
    ) = Finding(
        ruleId = ruleId, title = "Malicious Domain", level = "critical",
        category = FindingCategory.APP_RISK,
        evidence = com.androdr.sigma.Evidence.IocMatch(
            domain, iocType, "src", family, category, campaign = campaign, observedAt = observedAt,
        ),
        matchContext = mapOf(
            "domain" to domain, "source_package" to "com.android.shell",
            "is_blocked" to isBlocked, "reason" to reason,
        ),
    )

    @Suppress("LongParameterList")
    private fun formatReportWith(
        appRisks: List<Finding> = emptyList(),
        deviceFlags: List<Finding> = emptyList(),
        campaigns: List<Campaign> = emptyList(),
        scannerErrors: List<ScannerFailure> = emptyList(),
        ruleCategoryById: Map<String, String> = emptyMap(),
        scan: ScanResult = buildScan(appRisks = appRisks, deviceFlags = deviceFlags, scannerErrors = scannerErrors),
    ) = ReportFormatter.formatScanReport(
        scan, emptyList(), emptyList(), versionName = "test",
        campaigns = campaigns, ruleCategoryById = ruleCategoryById,
    )

    @Test
    fun `IOC finding shows its family and block state`() {
        val f = iocFinding(domain = "forti.external-muki.com", family = "Graphite (Paragon)",
            category = "NATION_STATE_SPYWARE", isBlocked = "false")
        val report = formatReportWith(appRisks = listOf(f))
        assertTrue(
            report.contains("Matched : forti.external-muki.com -> Graphite (Paragon) (NATION_STATE_SPYWARE)")
        )
        assertTrue(report.contains("Blocked : forti.external-muki.com no (blocking is off for threat-list domains)"))
    }

    @Test
    fun `blocklist-caught domain is listed with its family`() {
        val f = iocFinding(domain = "forti.external-muki.com", family = "Graphite (Paragon)",
            category = "", isBlocked = "true", reason = "blocklist")
        val report = formatReportWith(appRisks = listOf(f))
        // The "DNS IOC matches linked to:" row itself, not the Matched line (which also contains the text)
        assertTrue(report.lines().any { it.trim() == "[!!]  forti.external-muki.com -> Graphite (Paragon)" })
        assertTrue(report.contains("Blocked : forti.external-muki.com yes"))
    }

    @Test
    fun `older stored finding without family renders without a Matched line`() {
        val f = iocFinding(domain = "x.com", family = "", category = "", isBlocked = "true")
        assertFalse(formatReportWith(appRisks = listOf(f)).contains("Matched :"))
    }

    private fun blockedLine(reason: String): String? =
        formatReportWith(listOf(iocFinding("d.example", "Fam", "", "x", reason = reason)))
            .lines().firstOrNull { it.contains("Blocked :") }?.trim()

    @Test
    fun `Blocked line covers every reason`() {
        assertEquals("Blocked : d.example yes", blockedLine("IOC: d.example"))
        assertEquals("Blocked : d.example yes", blockedLine("blocklist"))
        assertEquals("Blocked : d.example no (blocking is off for threat-list domains)",
            blockedLine("IOC_detect: d.example"))
        assertEquals("Blocked : d.example no (blocklist blocking is off)", blockedLine("blocklist_detect"))
        val cold = "Blocked : d.example no (not checked by the tunnel: the threat list was not loaded " +
            "when queried; matched at scan time)"
        assertEquals(cold, blockedLine(""))
    }

    @Test
    fun `a domain finding from a different rule id still gets the Blocked line`() {
        val f = iocFinding("d.example", "Fam", "", "true", reason = "IOC: d.example", ruleId = "androdr-999")
        assertTrue(formatReportWith(listOf(f)).contains("Blocked : d.example yes"))
    }

    @Test
    fun `a DDNS finding without IocMatch evidence renders no Blocked line`() {
        val ddns = Finding(
            ruleId = "androdr-070", title = "Dynamic DNS", level = "medium",
            category = FindingCategory.APP_RISK,
            matchContext = mapOf("domain" to "x.duckdns.org", "source_package" to "com.a.b", "is_blocked" to "false"),
        )
        assertFalse(formatReportWith(listOf(ddns)).contains("Blocked :"))
    }

    @Test
    fun `an IOC domain list is printed even with no campaign-tagged device flag`() {
        val f = iocFinding("d.example", "Fam", "", "false")
        assertTrue(formatReportWith(listOf(f)).contains("DNS IOC matches linked to:"))
    }

    @Test
    fun `an imported scan renders no Blocked line`() {
        val f = iocFinding("d.example", "Fam", "", "false")
        val scan = buildScan(appRisks = listOf(f))
            .copy(source = com.androdr.data.model.TelemetrySource.BUGREPORT_IMPORT)
        val report = formatReportWith(listOf(f), scan = scan)
        assertTrue(report.contains("Matched : d.example -> Fam"))
        assertFalse(report.contains("Blocked :"))
    }

    @Test
    fun `FeedsNotLoaded prints under not-checked and raises no partial-scan banner`() {
        val entry = ScannerFailure("threat_intel", NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel,
            "threat-intel feeds not loaded yet")
        val scan = buildScan(scannerErrors = listOf(entry))
        val report = formatReportWith(emptyList(), scan = scan)
        assertFalse(scan.isPartialScan)
        assertTrue(report.contains(ReportFormatter.NOT_CHECKED_SECTION))
        assertTrue(report.contains(NotEvaluatedReason.FEEDS_NOT_LOADED.heading))
    }

    @Test
    fun `DnsMonitorOff says earlier lookups were checked`() {
        val entry = ScannerFailure("dns_monitor", NotEvaluatedReason.DNS_MONITOR_OFF.sentinel, "DNS monitoring was off")
        val f = iocFinding("d.example", "Fam", "", "false")
        val report = formatReportWith(listOf(f), scan = buildScan(appRisks = listOf(f), scannerErrors = listOf(entry)))
        assertTrue(report.contains("the most recent recorded lookups were checked"))
    }

    @Test
    fun `DNS IOC summary count equals the list size when the tunnel never matched`() {
        val f = iocFinding("d.example", "Fam", "", "false", reason = "")
        val dns = listOf(com.androdr.data.model.DnsEvent(
            timestamp = 1L, domain = "d.example", appUid = 1, appName = null, isBlocked = false, reason = null))
        val report = ReportFormatter.formatScanReport(
            buildScan(appRisks = listOf(f)), dns, emptyList(), versionName = "test")
        assertTrue(report, report.contains("DNS IOC matches: 1"))
        val listed = report.lines().dropWhile { !it.contains("DNS IOC matches linked to:") }
            .drop(1).takeWhile { it.trim().startsWith("[!!]") }
        assertEquals(1, listed.size)
    }

    @Test
    fun `fallback list from tunnel reasons renders with the domain indicator suffix`() {
        val dns = listOf(com.androdr.data.model.DnsEvent(
            timestamp = 1L, domain = "d.example", appUid = 1, appName = null, isBlocked = true,
            reason = "IOC: Pegasus"))
        val report = ReportFormatter.formatScanReport(
            buildScan(), dns, emptyList(), versionName = "test")
        assertTrue(report, report.lines().any { it.trim() == "[!!]  Pegasus (domain indicator)" })
        assertTrue(report, report.contains("DNS IOC matches: 1"))
    }

    @Test
    fun `the DNS IOC list has its own heading, never under the mercenary check`() {
        // A non-empty campaign list, as in production (the registry is never empty): a generic
        // feed hit must not render under MERCENARY SPYWARE CHECK (R7).
        val report = formatReportWith(listOf(iocFinding("0--4.com", "HaGeZi TIF", "", "false")),
            campaigns = listOf(Campaign("pegasus", "Pegasus")))
        assertTrue(report, report.contains("  DNS IOC MATCHES\n"))
        val mercenary = report.substringAfter("  MERCENARY SPYWARE CHECK\n")
            .substringAfter("------------------------------------------------------------\n")
            .substringBefore("------------------------------------------------------------")
        assertFalse(mercenary, mercenary.contains("HaGeZi"))
        assertFalse(mercenary, mercenary.contains("DNS IOC matches linked to"))
    }
}
