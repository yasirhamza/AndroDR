package com.androdr.reporting

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.TelemetrySource
import com.androdr.ioc.Campaign
import com.androdr.ioc.CampaignRegistry
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** The bundled vocabulary generated in Task B3 — the same file CampaignRegistry falls back to. */
private val REGISTRY: List<Campaign> by lazy {
    val f = listOf(File("src/main/res/raw/known_campaigns.json"), File("app/src/main/res/raw/known_campaigns.json"))
        .first { it.isFile }
    CampaignRegistry.parseBundled(f.readText())
}
private fun campaign(key: String) = REGISTRY.single { it.key == key }

/** What the real bundle's campaign detectors can see, as ReportInputs.ruleScopes() builds it. */
private val BUNDLE_SCOPES: Map<String, RuleScope> = mapOf(
    "androdr-001" to RuleScope("app_scanner", emptySet(), true),
    "androdr-003" to RuleScope("dns_monitor", emptySet(), true),
    "androdr-078" to RuleScope("app_scanner", setOf("massistant"), false),
    "androdr-108" to RuleScope("file_scanner", setOf("predator"), false),
    "androdr-109" to RuleScope("app_scanner", setOf("midnight-mimosa"), false),
)

/**
 * The report's MERCENARY SPYWARE CHECK (B7): one row per campaign, attributed IOC hits counted
 * within 30 days, DETECTED / EXPOSED / earlier hit / import / not detected. Split from
 * ReportFormatterTest (detekt LargeClass); same report entry point and fixtures.
 */
class MercenaryCheckReportTest {

    private val scanTime = 1711900800000L

    private fun buildScan(
        appRisks: List<Finding> = emptyList(),
        deviceFlags: List<Finding> = emptyList(),
        scannerErrors: List<ScannerFailure> = emptyList(),
    ): ScanResult = ScanResult(
        id = 1L, timestamp = scanTime, findings = deviceFlags + appRisks, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = scannerErrors,
    )

    @Suppress("LongParameterList")
    private fun iocFinding(
        domain: String,
        family: String,
        category: String,
        isBlocked: String,
        campaign: String = "",
        observedAt: Long = scanTime,
        iocType: String = "domain",
    ) = Finding(
        ruleId = "androdr-003", title = "Malicious Domain", level = "critical",
        category = FindingCategory.APP_RISK,
        evidence = Evidence.IocMatch(
            domain, iocType, "src", family, category, campaign = campaign, observedAt = observedAt,
        ),
        matchContext = mapOf(
            "domain" to domain, "source_package" to "com.android.shell",
            "is_blocked" to isBlocked, "reason" to "IOC_detect: $domain",
        ),
    )

    private fun formatReportWith(
        appRisks: List<Finding> = emptyList(),
        deviceFlags: List<Finding> = emptyList(),
        campaigns: List<Campaign> = emptyList(),
        scannerErrors: List<ScannerFailure> = emptyList(),
        ruleCategoryById: Map<String, String> = emptyMap(),
        ruleScopes: Map<String, RuleScope> = BUNDLE_SCOPES,
    ) = reportText(
        buildScan(appRisks, deviceFlags, scannerErrors),
        campaigns = campaigns, ruleScopes = ruleScopes, ruleCategoryById = ruleCategoryById,
    )

    private fun formatImportReportWith(
        appRisks: List<Finding>,
        deviceFlags: List<Finding> = emptyList(),
        intrusionEvents: List<ForensicTimelineEvent> = emptyList(),
        campaigns: List<Campaign>,
        source: TelemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT,
        scannerErrors: List<ScannerFailure> = emptyList(),
    ) = reportText(
        buildScan(appRisks = appRisks, deviceFlags = deviceFlags, scannerErrors = scannerErrors)
            .copy(source = source),
        // The import's latest stored event: the window the campaign rows count back from.
        telemetry = FakeTelemetry(latestEvent = intrusionEvents.maxOfOrNull { it.startTimestamp }),
        campaigns = campaigns,
    )

    private fun importedEvent(at: Long) = ForensicTimelineEvent(
        startTimestamp = at, source = "intrusion_log", category = "dns_query",
        description = "DNS query", telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT,
    )

    private fun cveCampaignFinding(tags: List<String>, triggered: Boolean, ruleCategory: String = "") = Finding(
        ruleId = "androdr-048", title = "Unpatched exploited CVE", level = "medium",
        category = FindingCategory.DEVICE_POSTURE, tags = tags, triggered = triggered,
        ruleCategory = ruleCategory,
    )

    private fun taggedFinding(ruleId: String, title: String, category: FindingCategory, tags: List<String>) =
        Finding(ruleId = ruleId, title = title, level = "high", category = category, tags = tags, triggered = true)

    @Test
    fun `recent Graphite IOC hit marks Graphite detected with its date`() {
        val report = formatReportWith(
            appRisks = listOf(iocFinding("forti.external-muki.com", "Graphite (Paragon)", "NATION_STATE_SPYWARE",
                "false", campaign = "graphite", observedAt = scanTime - DAY)),
            campaigns = listOf(campaign("graphite")))
        assertTrue(report.contains(
            "[!!]  Graphite (Paragon): DETECTED -- domain forti.external-muki.com (Graphite (Paragon)), "))
    }

    @Test
    fun `IOC hit older than 30 days does not mark detected`() {
        val report = formatReportWith(
            appRisks = listOf(iocFinding("forti.external-muki.com", "Graphite (Paragon)", "", "false",
                campaign = "graphite", observedAt = scanTime - 31 * DAY)),
            campaigns = listOf(campaign("graphite")))
        assertTrue(report.contains(
            "[--]  Graphite (Paragon): earlier hit only -- domain forti.external-muki.com (Graphite (Paragon)), "))
        assertFalse(report.contains("[OK]  Graphite (Paragon): not detected"))
        assertFalse(report.lines().first { it.contains("Campaign detections") }.contains("Graphite"))
    }

    @Test
    fun `unpatched device with an old hit stays EXPOSED and on the exposure line`() {
        val cve = cveCampaignFinding(
            tags = listOf("campaign.pegasus"), triggered = true, ruleCategory = "DEVICE_POSTURE")
        val report = formatReportWith(deviceFlags = listOf(cve),
            appRisks = listOf(iocFinding("old.example", "Pegasus", "", "false", campaign = "pegasus",
                observedAt = scanTime - 31 * DAY)),
            campaigns = listOf(campaign("pegasus")))
        assertTrue(report.contains("[!!]  ${campaign("pegasus").label}: EXPOSED -- "))
        assertTrue(report.contains("also an earlier hit -- domain old.example (Pegasus), "))
        assertTrue(report.contains("(over 30 days before this scan)"))
        assertTrue(report.lines().first { it.contains("Campaign exposure (unpatched)") }
            .contains(campaign("pegasus").label))
        assertFalse(report.lines().first { it.contains("Campaign detections") }.contains(campaign("pegasus").label))
        assertFalse(report.contains("${campaign("pegasus").label}: earlier hit only")) // one row, not two (Q17-3)
    }

    @Test
    fun `import never renders EXPOSED`() {
        val cve = cveCampaignFinding(
            tags = listOf("campaign.pegasus"), triggered = true, ruleCategory = "DEVICE_POSTURE")
        val report = formatImportReportWith(appRisks = emptyList(), deviceFlags = listOf(cve),
            campaigns = listOf(campaign("pegasus")))
        assertFalse(report.contains("EXPOSED"))
        assertTrue(report.contains("${campaign("pegasus").label}: no hit in the imported log"))
    }

    @Test
    fun `import with an old hit says earlier hit, not no hit`() {
        val logLatest = scanTime - 2 * DAY
        val report = formatImportReportWith(
            appRisks = listOf(iocFinding("forti.external-muki.com", "Graphite (Paragon)", "", "false",
                campaign = "graphite", observedAt = logLatest - 31 * DAY)),
            intrusionEvents = listOf(importedEvent(at = logLatest)), campaigns = listOf(campaign("graphite")))
        assertTrue(report.contains("Graphite (Paragon): earlier hit only -- "))
        assertTrue(report.contains("(over 30 days before the log's latest event)"))
        assertFalse(report.contains("Graphite (Paragon): no hit in the imported log"))
    }

    @Test
    fun `a future-dated imported record does not push a recent hit out of the window`() {
        // One record parsed with a far-future time (a corrupt line, a clock set ahead) must not become
        // the reference time: the hit two days before the import still reads DETECTED.
        val report = formatImportReportWith(
            appRisks = listOf(iocFinding("forti.external-muki.com", "Graphite (Paragon)", "", "false",
                campaign = "graphite", observedAt = scanTime - 2 * DAY)),
            intrusionEvents = listOf(importedEvent(at = scanTime + 400 * DAY)),
            campaigns = listOf(campaign("graphite")))
        assertTrue(report, report.contains("[!!]  Graphite (Paragon): DETECTED -- "))
        assertFalse(report, report.contains("earlier hit only"))
    }

    @Test
    fun `campaign-tagged app-risk finding marks its campaign detected`() {
        // androdr-109: tag campaign.midnight-mimosa, display.category app_risk -- not a CVE finding
        val f = taggedFinding(ruleId = "androdr-109", title = "Midnight Mimosa preinstalled enabler",
            category = FindingCategory.APP_RISK, tags = listOf("campaign.midnight-mimosa"))
        val report = formatReportWith(appRisks = listOf(f), campaigns = listOf(campaign("midnight-mimosa")))
        assertTrue(report.contains(
            "[!!]  ${campaign("midnight-mimosa").label}: DETECTED -- Midnight Mimosa preinstalled enabler"))
        assertFalse(report.contains("${campaign("midnight-mimosa").label}: not detected"))
    }

    @Test
    fun `import never claims a campaign was checked and not found`() {
        for (source in listOf(TelemetrySource.INTRUSION_LOG_IMPORT, TelemetrySource.BUGREPORT_IMPORT)) {
            val report = formatImportReportWith(appRisks = emptyList(), deviceFlags = emptyList(),
                campaigns = listOf(campaign("pegasus")), source = source)
            assertTrue(report.contains(
                "[--]  ${campaign("pegasus").label}: no hit in the imported log (device checks not run)"))
            assertFalse(report.contains("[OK]  ${campaign("pegasus").label}"))
        }
    }

    @Test
    fun `legacy campaign without detected_by keeps today's row and the note`() {
        val legacy = Campaign("pegasus", "Pegasus")
        val report = formatReportWith(campaigns = listOf(legacy),
            scannerErrors = listOf(ScannerFailure(scanner = "threat_intel",
                exception = NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel,
                message = "threat-intel feeds not loaded yet")))
        assertTrue(report.contains("[OK]  Pegasus: not detected"))
        assertTrue(report.contains("\"not detected\" means none of the checks that ran in this scan matched."))
        assertTrue(report.contains("1 check(s) could not run -- see ${ReportFormatter.NOT_CHECKED_SECTION} below."))
    }

    @Test
    fun `no scope extras when nothing failed, none on imports`() {
        val live = formatReportWith(campaigns = listOf(campaign("pegasus")))
        assertFalse(live.contains("check(s) could not run"))
        assertFalse(live.contains("scanner(s) failed"))
        val import = formatImportReportWith(appRisks = emptyList(), campaigns = listOf(campaign("pegasus")))
        assertFalse(import.contains("\"not detected\" means"))
    }

    /** Final review item 2(b): an import's failed checks are said under its campaign rows. */
    @Test
    fun `import with a failed attribution prefetch says so under the campaign rows`() {
        val report = formatImportReportWith(appRisks = emptyList(), campaigns = listOf(campaign("pegasus")),
            scannerErrors = listOf(ScannerFailure(scanner = "attribution", exception = "SQLiteException",
                message = "family unavailable: domain prefetch failed")))
        val row = "  [--]  ${campaign("pegasus").label}: no hit in the imported log (device checks not run)"
        val lines = report.lines()
        val at = lines.indexOf(row)
        assertTrue(report, at >= 0) // import row wording unchanged
        assertEquals("  1 scanner(s) failed on this scan; their checks did not run.", lines[at + 1])
        assertFalse(report.contains("\"not detected\" means"))
    }

    @Test
    fun `import with a could-not-run entry points at the could-not-check section`() {
        val report = formatImportReportWith(appRisks = emptyList(), campaigns = listOf(campaign("pegasus")),
            scannerErrors = listOf(ScannerFailure(scanner = "threat_intel",
                exception = NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel,
                message = "threat-intel feeds not loaded yet")))
        val lines = report.lines()
        val at = lines.indexOf(
            "  [--]  ${campaign("pegasus").label}: no hit in the imported log (device checks not run)")
        assertEquals("  1 check(s) could not run -- see ${ReportFormatter.NOT_CHECKED_SECTION} below.", lines[at + 1])
    }

    @Test
    fun `crashed scanner gets its own line, not a pointer to an empty section`() {
        val report = formatReportWith(campaigns = listOf(campaign("pegasus")),
            scannerErrors = listOf(ScannerFailure(scanner = "appScanner", exception = "IllegalStateException",
                message = "boom")))
        assertTrue(report.contains("1 scanner(s) failed on this scan; their checks did not run."))
        assertFalse(report.contains("check(s) could not run -- see"))
    }

    @Test
    fun `Cellebrite package hit marks its campaign detected`() {
        // The one real campaign-tagged package in ioc-data (mvt-indicators, campaign: cellebrite).
        val report = formatReportWith(
            appRisks = listOf(iocFinding("com.client.appA", "Cellebrite", "FORENSIC_TOOL", "",
                campaign = "cellebrite", observedAt = 0L, iocType = "package")),
            campaigns = REGISTRY)
        assertTrue(report.contains(
            "[!!]  ${campaign("cellebrite").label}: DETECTED -- package com.client.appA (Cellebrite), "))
        // Massistant has no IOC entries any more, but its key still renders as a row.
        assertTrue(report.contains("[OK]  ${campaign("massistant").label}: not detected"))
    }

    @Test
    fun `generic feed hit never marks a campaign detected`() {
        val report = formatReportWith(
            appRisks = listOf(iocFinding("0--4.com", "HaGeZi TIF", "", "false", campaign = "", observedAt = scanTime)),
            campaigns = listOf(campaign("pegasus")))
        assertFalse(report.contains("DETECTED"))
    }

    @Test
    fun `campaign rows render for an intrusion-log import`() {
        val report = formatImportReportWith(
            appRisks = listOf(iocFinding("forti.external-muki.com", "Graphite (Paragon)", "", "false",
                campaign = "graphite", observedAt = scanTime - DAY)),
            campaigns = listOf(campaign("graphite")))
        assertTrue(report.contains("Graphite (Paragon): DETECTED"))
    }

    @Test
    fun `45-day-old import still shows the campaign relative to the log`() {
        val logLatest = scanTime - 45 * DAY
        val report = formatImportReportWith(
            appRisks = listOf(iocFinding("forti.external-muki.com", "Graphite (Paragon)", "", "false",
                campaign = "graphite", observedAt = logLatest - DAY)),
            intrusionEvents = listOf(importedEvent(at = logLatest)), campaigns = listOf(campaign("graphite")))
        assertTrue(report.contains("Graphite (Paragon): DETECTED"))
    }

    @Test
    fun `dual-tag CVE rule plus graphite IOC hit marks Graphite detected`() {
        // e.g. tags campaign.paragon + campaign.graphite on one CVE finding
        val cve = cveCampaignFinding(tags = listOf("campaign.paragon", "campaign.graphite"), triggered = false)
        val report = formatReportWith(deviceFlags = listOf(cve),
            appRisks = listOf(iocFinding("forti.external-muki.com", "Graphite (Paragon)", "", "false",
                campaign = "graphite", observedAt = scanTime)),
            campaigns = listOf(campaign("graphite"))) // one row: graphite with alias paragon
        assertTrue(report.contains("[!!]  Graphite (Paragon): DETECTED"))
        assertFalse(report.contains("Paragon: not detected"))
        assertEquals(1, Regex("""Graphite \(Paragon\): """)
            .findAll(report.substringAfter("MERCENARY SPYWARE CHECK").substringBefore("\n\n\n")).count())
    }

    @Test
    fun `paragon-tagged CVE finding plus graphite IOC hit gives exactly one Graphite row`() {
        val cve = cveCampaignFinding(tags = listOf("campaign.paragon"), triggered = false)
        val report = formatReportWith(deviceFlags = listOf(cve),
            appRisks = listOf(iocFinding("forti.external-muki.com", "Graphite (Paragon)", "", "false",
                campaign = "graphite", observedAt = scanTime)),
            campaigns = REGISTRY)
        val section = report.substringAfter("MERCENARY SPYWARE CHECK").substringBefore("APP RISKS")
        assertEquals(1, section.lines().count { it.contains("Graphite (Paragon): ") })
        assertTrue(section.contains("[!!]  Graphite (Paragon): DETECTED"))
        assertFalse(section.contains("Paragon:"))
    }

    @Test
    fun `summary detection line and section list the same campaigns`() {
        val report = formatReportWith(
            appRisks = listOf(
                iocFinding("forti.external-muki.com", "Graphite (Paragon)", "", "false", campaign = "graphite",
                    observedAt = scanTime),
                taggedFinding("androdr-109", "Midnight Mimosa preinstalled enabler", FindingCategory.APP_RISK,
                    listOf("campaign.midnight-mimosa")),
            ),
            campaigns = REGISTRY)
        val detectedInSection = report.lines().filter { it.contains(": DETECTED -- ") }
            .map { it.substringAfter("[!!]  ").substringBefore(": DETECTED") }.toSet()
        val summary = report.lines().first { it.contains("Campaign detections:") }
            .substringAfter("Campaign detections: ").split(", ").toSet()
        assertEquals(setOf("Graphite (Paragon)", "Midnight Mimosa"), detectedInSection)
        assertEquals(detectedInSection, summary)
    }

    @Test
    fun `unknown campaign key from a rule tag still gets a row`() {
        // Rule content is hash-pinned, so a tag the registry doesn't know yet is still shown.
        val cve = cveCampaignFinding(tags = listOf("campaign.newcampaign"), triggered = true)
        val report = formatReportWith(deviceFlags = listOf(cve), campaigns = listOf(campaign("pegasus")))
        assertTrue(report.contains("[!!]  Newcampaign: DETECTED"))
    }

    @Test
    fun `unknown campaign key from IOC data is ignored`() {
        // Spec section 3.1a: the app ignores unknown keys from data.
        val report = formatReportWith(
            appRisks = listOf(iocFinding("x.example", "Some family", "", "false", campaign = "unknownkey",
                observedAt = scanTime)),
            campaigns = listOf(campaign("pegasus")))
        assertFalse(report.contains("Unknownkey"))
    }

    @Test
    fun `package hit with no observation time uses the scan time`() {
        val report = formatReportWith(
            appRisks = listOf(iocFinding("com.serv.services", "NoviSpy", "NATION_STATE_SPYWARE", "",
                campaign = "testcampaign", observedAt = 0L, iocType = "package")),
            // synthetic key on purpose: this test is about the observedAt = 0 fallback, not the vocabulary
            campaigns = listOf(Campaign("testcampaign", "Test campaign")))
        assertTrue(report.contains("[!!]  Test campaign: DETECTED -- package com.serv.services (NoviSpy), "))
    }

    // -- EXPOSED vs DETECTED (owner decision 2026-10-16, Q9-3) --------------------

    @Test
    fun `triggered patch-level CVE rule marks EXPOSED, not a detection`() {
        val cve = cveCampaignFinding(
            tags = listOf("campaign.pegasus"), triggered = true, ruleCategory = "DEVICE_POSTURE")
        val report = formatReportWith(deviceFlags = listOf(cve), campaigns = listOf(campaign("pegasus")))
        assertTrue(report.contains(
            "[!!]  Pegasus: EXPOSED -- Unpatched exploited CVE (unpatched; not evidence of infection)"))
        assertFalse(report.lines().first { it.contains("Campaign detections") }.contains("Pegasus"))
        assertTrue(report.lines().first { it.contains("Campaign exposure (unpatched)") }.contains("Pegasus"))
    }

    @Test
    fun `patch-level CVE rule plus a recent IOC hit is DETECTED only`() {
        val cve = cveCampaignFinding(
            tags = listOf("campaign.pegasus"), triggered = true, ruleCategory = "DEVICE_POSTURE")
        val report = formatReportWith(deviceFlags = listOf(cve),
            appRisks = listOf(iocFinding("p.example", "Pegasus", "", "false", campaign = "pegasus",
                observedAt = scanTime)),
            campaigns = listOf(campaign("pegasus")))
        assertTrue(report.contains("[!!]  Pegasus: DETECTED -- domain p.example (Pegasus), "))
        assertFalse(report.contains("EXPOSED"))
        assertFalse(report.contains("Campaign exposure (unpatched)"))
        assertTrue(report.lines().first { it.contains("Campaign detections") }.contains("Pegasus"))
    }

    @Test
    fun `stored finding without a rule category whose rule is not loaded is DETECTED`() {
        val cve = cveCampaignFinding(tags = listOf("campaign.pegasus"), triggered = true)
        val report = formatReportWith(deviceFlags = listOf(cve), campaigns = listOf(campaign("pegasus")))
        assertTrue(report.contains("[!!]  Pegasus: DETECTED -- Unpatched exploited CVE"))
    }

    @Test
    fun `stored finding without a rule category takes its loaded rule's category`() {
        val cve = cveCampaignFinding(tags = listOf("campaign.pegasus"), triggered = true)
        val report = formatReportWith(deviceFlags = listOf(cve), campaigns = listOf(campaign("pegasus")),
            ruleCategoryById = mapOf(cve.ruleId to "DEVICE_POSTURE"))
        assertTrue(report.contains("[!!]  Pegasus: EXPOSED -- Unpatched exploited CVE"))
    }

    @Test
    fun `clean live device - fully checked campaigns are OK, LANDFALL has no infection check`() {
        val report = formatReportWith(campaigns = REGISTRY)
        REGISTRY.filter { it.key != "landfall" }
            .forEach { assertTrue(it.key, report.contains("  [OK]  ${it.label}: not detected")) }
        assertTrue(report.contains("  [--]  LANDFALL: no infection check exists for a live scan; patch level only"))
        assertFalse("every row carries its own reason", report.contains("\"not detected\" means"))
        assertTrue(report.contains("Campaign detections: none"))
    }

    private val dnsOff = ScannerFailure(scanner = "dns_monitor",
        exception = NotEvaluatedReason.DNS_MONITOR_OFF.sentinel, message = "DNS monitoring was off")
    private val dnsOffClause =
        "DNS lookups not monitored (DNS monitoring was off; only lookups recorded earlier were checked)"
    private val dnsOffFix = "        Turn on DNS monitoring, use the phone as usual, then scan again."

    @Test
    fun `dns off - a dns-only campaign is not fully checked and says how to fix it`() {
        val lines = formatReportWith(campaigns = listOf(campaign("pegasus")), scannerErrors = listOf(dnsOff)).lines()
        val at = lines.indexOf("  [--]  Pegasus: $dnsOffClause")
        assertTrue(lines.joinToString("\n"), at >= 0)
        assertEquals(dnsOffFix, lines[at + 1])
    }

    @Test
    fun `dns off - a two-service campaign names what was checked and what was not`() {
        val report = formatReportWith(campaigns = listOf(campaign("midnight-mimosa")), scannerErrors = listOf(dnsOff))
        assertTrue(report, report.contains("  [--]  Midnight Mimosa: no hit in installed apps; $dnsOffClause"))
    }

    @Test
    fun `a crashed scanner says the check failed`() {
        val report = formatReportWith(campaigns = listOf(campaign("massistant")),
            scannerErrors = listOf(ScannerFailure("appScanner", "IllegalStateException", "boom")))
        assertTrue(report, report.contains(
            "  [--]  Massistant: installed apps not checked (that check failed on this scan)"))
        assertTrue(report, report.contains(
            "        Scan again; if it keeps failing, export the report and send it to us."))
    }

    @Test
    fun `this campaign's unreadable file paths leave it partly checked`() {
        val report = formatReportWith(campaigns = listOf(campaign("predator")),
            ruleScopes = BUNDLE_SCOPES + mapOf("androdr-108" to RuleScope("file_scanner", setOf("predator"), false)),
            scannerErrors = listOf(ScannerFailure("file_scanner", NotEvaluatedReason.UNREADABLE_PATHS.sentinel,
                "Predator (androdr-108): 3 of 5 path(s) could not be read", ruleId = "androdr-108")))
        assertTrue(report, report.contains(
            "  [--]  Predator: no hit in DNS lookups; files only partly checked (some paths could not be read)"))
    }

    @Test
    fun `a shared fix is printed once`() {
        val report = formatReportWith(campaigns = listOf(campaign("midnight-mimosa")),
            scannerErrors = listOf(ScannerFailure("threat_intel", NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel, "x")))
        assertTrue(report, report.contains(
            "  [--]  Midnight Mimosa: installed apps checked against the built-in list " +
            "only (threat lists had not finished loading); DNS lookups checked against the built-in list only " +
            "(threat lists had not finished loading)"))
        assertEquals(1, Regex("Scan again in a few minutes\\.").findAll(report).count())
    }

    @Test
    fun `unknown service fails closed`() {
        val future = Campaign("pegasus", "Pegasus", detectedBy = listOf("usage_stats"))
        val report = formatReportWith(campaigns = listOf(future))
        assertTrue(report, report.contains(
            "  [--]  Pegasus: usage_stats not checked (this app version does not know that check)"))
        assertTrue(report, report.contains("        Update the app."))
    }

    @Test
    fun `skipped rules leave a service partly checked`() {
        val report = formatReportWith(campaigns = listOf(campaign("pegasus")),
            ruleScopes = mapOf("androdr-003" to RuleScope("dns_monitor", emptySet(), true)),
            scannerErrors = listOf(ScannerFailure("x", NotEvaluatedReason.MISSING_CAPABILITY.sentinel, "m",
                ruleId = "androdr-003")))
        val lines = report.lines()
        val at = lines.indexOf(
            "  [--]  Pegasus: DNS lookups only partly checked (some of its rules could not run on this app version)")
        assertTrue(report, at >= 0)
        assertEquals("        Update the app.", lines[at + 1])
    }

    @Test
    fun `a failed attribution step says hits could not be matched to campaigns`() {
        val report = formatReportWith(campaigns = listOf(campaign("pegasus")),
            scannerErrors = listOf(ScannerFailure("attribution", "MissingPrefetch", "m")))
        val lines = report.lines()
        val at = lines.indexOf("  [--]  Pegasus: DNS lookups checked, but hits could not be matched to campaigns " +
            "(that step failed on this scan)")
        assertTrue(report, at >= 0)
        assertEquals("        Scan again; if it keeps failing, export the report and send it to us.", lines[at + 1])
    }

    @Test
    fun `unknown feed state says it is not known whether threat lists had loaded`() {
        val report = formatReportWith(campaigns = listOf(campaign("massistant")),
            scannerErrors = listOf(ScannerFailure("visibility_gaps", "SQLiteException", "m")))
        val lines = report.lines()
        val at = lines.indexOf(
            "  [--]  Massistant: installed apps checked, but it is not known whether the threat lists had loaded")
        assertTrue(report, at >= 0)
        assertEquals("        Scan again in a few minutes.", lines[at + 1])
    }

    @Test
    fun `no loaded detector - no campaign reads OK and the row says the rule was not loaded`() {
        val report = formatReportWith(campaigns = REGISTRY, ruleScopes = emptyMap())
        assertFalse(report, report.contains("[OK]"))
        val lines = report.lines()
        val at = lines.indexOf("  [--]  Pegasus: DNS lookups not checked (the rule that detects it was not loaded)")
        assertTrue(report, at >= 0)
        assertEquals("        Scan again later; if it persists, update the app.", lines[at + 1])
    }

    @Test
    fun `exposed carries the infection-check summary`() {
        val cve = cveCampaignFinding(
            tags = listOf("campaign.pegasus"), triggered = true, ruleCategory = "DEVICE_POSTURE")
        val report = formatReportWith(deviceFlags = listOf(cve), campaigns = listOf(campaign("pegasus")),
            scannerErrors = listOf(dnsOff))
        assertTrue(report, report.contains("  [!!]  Pegasus: EXPOSED -- Unpatched exploited CVE (unpatched; not " +
            "evidence of infection); infection check: $dnsOffClause"))
        val clean = formatReportWith(deviceFlags = listOf(cve), campaigns = listOf(campaign("pegasus")))
        assertTrue(clean, clean.contains("(unpatched; not evidence of infection); infection check: not detected"))
    }

    @Test
    fun `import rows are unchanged even with detected_by`() {
        val report = formatImportReportWith(appRisks = emptyList(), campaigns = listOf(campaign("pegasus")))
        assertTrue(report, report.contains("  [--]  Pegasus: no hit in the imported log (device checks not run)"))
        assertFalse(report, report.contains("infection check"))
    }

    // -- Fix round 1 -------------------------------------------------------------

    @Test
    fun `import package hit with no observation time is dated and windowed at the log's latest event`() {
        val logLatest = scanTime - 45 * DAY
        val report = formatImportReportWith(
            appRisks = listOf(iocFinding("com.client.appA", "Cellebrite", "", "", campaign = "cellebrite",
                observedAt = 0L, iocType = "package")),
            intrusionEvents = listOf(importedEvent(at = logLatest)), campaigns = listOf(campaign("cellebrite")))
        val date = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US).format(java.util.Date(logLatest))
        assertTrue(report, report.contains("[!!]  Cellebrite: DETECTED -- package com.client.appA (Cellebrite), $date"))
    }

    @Test
    fun `import earlier hit without log events does not claim the log's latest event`() {
        val report = formatImportReportWith(
            appRisks = listOf(
                iocFinding("forti.external-muki.com", "Graphite (Paragon)", "", "false", campaign = "graphite",
                    observedAt = scanTime - 40 * DAY),
                iocFinding("p.example", "Pegasus", "", "false", campaign = "pegasus", observedAt = scanTime),
            ),
            campaigns = listOf(campaign("graphite"), campaign("pegasus")))
        assertTrue(report, report.contains("Graphite (Paragon): earlier hit only -- "))
        assertFalse(report, report.contains("the log's latest event"))
        assertTrue(report, report.contains("(over 30 days before the latest dated hit in this import)"))
    }

    @Test
    fun `a hit exactly 30 days old still counts, one millisecond more does not`() {
        val at30 = formatReportWith(
            appRisks = listOf(iocFinding("p.example", "Pegasus", "", "false", campaign = "pegasus",
                observedAt = scanTime - 30 * DAY)),
            campaigns = listOf(campaign("pegasus")))
        assertTrue(at30.contains("[!!]  Pegasus: DETECTED -- "))
        val over = formatReportWith(
            appRisks = listOf(iocFinding("p.example", "Pegasus", "", "false", campaign = "pegasus",
                observedAt = scanTime - 30 * DAY - 1)),
            campaigns = listOf(campaign("pegasus")))
        assertTrue(over.contains("[--]  Pegasus: earlier hit only -- "))
    }

    @Test
    fun `a DETECTED row comes before an alphabetically earlier not-detected row`() {
        val report = formatReportWith(
            appRisks = listOf(iocFinding("p.example", "Pegasus", "", "false", campaign = "pegasus")),
            campaigns = REGISTRY)
        val detected = report.indexOf("[!!]  Pegasus: DETECTED")
        val cellebrite = report.indexOf("[OK]  Cellebrite: not detected")
        assertTrue(detected in 0 until cellebrite)
    }

    @Test
    fun `an untriggered finding with a campaign key does not mark the campaign detected`() {
        val report = formatReportWith(
            appRisks = listOf(
                iocFinding("p.example", "Pegasus", "", "false", campaign = "pegasus").copy(triggered = false)),
            campaigns = listOf(campaign("pegasus")))
        assertFalse(report.contains("DETECTED"))
        assertTrue(report.contains("[OK]  Pegasus: not detected"))
    }

    private companion object {
        const val DAY = 86_400_000L
    }
}
