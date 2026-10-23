package com.androdr.reporting

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ScanResult
import com.androdr.network.ConnectionOwnerResolver
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The report's DNS rows and app-risk grouping must show WHICH app talked to a
 * domain. Before this every row read `<- unknown` and a DNS-rule finding, whose
 * only app key is `source_package`, was grouped under "unknown".
 */
class DnsAttributionReportTest {

    private fun scanOf(vararg findings: Finding) = ScanResult(
        id = 1L, timestamp = 1711900800000, findings = findings.toList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = emptyList(),
    )

    private fun dns(domain: String, uid: Int, pkg: String?, reason: String? = null) = DnsEvent(
        timestamp = 1711900800000, domain = domain, appUid = uid, appName = pkg, isBlocked = false, reason = reason,
    )

    private val names = mapOf("com.instagram.android" to "Instagram")

    @Test
    fun `an attributed DNS row names the app and its package`() {
        val text = ReportFormatter.formatScanReport(
            scanOf(), listOf(dns("graph.instagram.com", 10042, "com.instagram.android")), emptyList(),
            displayNames = names, versionName = "test",
            campaigns = emptyList(),
            ruleScopes = emptyMap(), ruleCategoryById = emptyMap(),
        )

        assertTrue(text, text.contains("graph.instagram.com"))
        assertTrue(text, text.contains("<- Instagram (com.instagram.android)"))
    }

    @Test
    fun `a query made by the system resolver is labelled as such, not unknown`() {
        val text = ReportFormatter.formatScanReport(
            scanOf(), listOf(dns("mtalk.google.com", ConnectionOwnerResolver.DNS_RESOLVER_UID, null)), emptyList(),
            versionName = "test",
            campaigns = emptyList(),
            ruleScopes = emptyMap(), ruleCategoryById = emptyMap(),
        )

        assertTrue(text, text.contains("<- system resolver"))
        assertTrue(!text.contains("<- unknown"))
    }

    @Test
    fun `an unattributed query still reads unknown`() {
        val text = ReportFormatter.formatScanReport(
            scanOf(), listOf(dns("example.com", ConnectionOwnerResolver.UNKNOWN_UID, null)), emptyList(),
            versionName = "test",
            campaigns = emptyList(),
            ruleScopes = emptyMap(), ruleCategoryById = emptyMap(),
        )

        assertTrue(text, text.contains("<- unknown"))
    }

    @Test
    fun `a DNS-rule finding is grouped under the querying app, not unknown`() {
        val c2 = Finding(
            ruleId = "androdr-003", title = "Known C2 Domain Contacted", level = "critical",
            category = FindingCategory.APP_RISK, triggered = true,
            guidance = "INVESTIGATE -- device contacted a known C2 server",
            matchContext = mapOf("domain" to "c2.evil.example", "source_package" to "com.evil.app"),
        )

        val text = ReportFormatter.formatScanReport(
            scanOf(c2), emptyList(), emptyList(), versionName = "test", mode = ExportMode.FINDINGS_ONLY,
            campaigns = emptyList(),
            ruleScopes = emptyMap(), ruleCategoryById = emptyMap(),
        )
        val apps = text.substring(text.indexOf("APP RISKS"))

        assertTrue(apps, apps.contains("com.evil.app"))
        assertTrue("grouped under unknown: $apps", !apps.contains("unknown"))
    }

    @Test
    fun `an unchecked event for a domain the scan matched reads NOT CHECKED`() {
        val text = ReportFormatter.formatScanReport(
            scanOf(iocDomainFinding("c2.evil.example", "NoviSpy")),
            listOf(dns("c2.evil.example", 10042, "com.evil.app", reason = null)), emptyList(),
            versionName = "test",
            campaigns = emptyList(),
            ruleScopes = emptyMap(), ruleCategoryById = emptyMap(),
        )

        assertTrue(text, text.contains("[NOT CHECKED]  "))
        assertTrue(text, text.contains("reason: threat list not yet loaded when queried; matched at scan time"))
    }

    @Test
    fun `an unchecked event for an unmatched domain stays ALLOWED`() {
        val text = ReportFormatter.formatScanReport(
            scanOf(iocDomainFinding("c2.evil.example", "NoviSpy")),
            listOf(dns("example.com", 10042, "com.evil.app", reason = null)), emptyList(),
            versionName = "test",
            campaigns = emptyList(),
            ruleScopes = emptyMap(), ruleCategoryById = emptyMap(),
        )

        assertTrue(text, text.contains("[ALLOWED]  "))
        assertTrue(text, !text.contains("[NOT CHECKED]"))
    }

    @Test
    fun `a tunnel-matched event stays MATCHED`() {
        val text = ReportFormatter.formatScanReport(
            scanOf(iocDomainFinding("c2.evil.example", "NoviSpy")),
            listOf(dns("c2.evil.example", 10042, "com.evil.app", reason = "IOC_detect: c2.evil.example")),
            emptyList(), versionName = "test",
            campaigns = emptyList(),
            ruleScopes = emptyMap(), ruleCategoryById = emptyMap(),
        )

        assertTrue(text, text.contains("[MATCHED]  "))
        assertTrue(text, !text.contains("[NOT CHECKED]"))
    }

    private fun iocDomainFinding(domain: String, family: String) = Finding(
        ruleId = "androdr-003", title = "Malicious Domain", level = "critical",
        category = FindingCategory.APP_RISK, triggered = true,
        evidence = com.androdr.sigma.Evidence.IocMatch(domain, "domain", "src", family),
        matchContext = mapOf("domain" to domain, "source_package" to "com.evil.app"),
    )
}
