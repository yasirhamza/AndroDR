package com.androdr.reporting

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.scanWith
import com.androdr.network.ConnectionOwnerResolver
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The report must show WHICH app talked to a domain. Before attribution every DNS row read
 * `<- unknown` and a DNS-rule finding, whose only app key is `source_package`, was grouped under
 * "unknown". Since Phase B the DNS rows are the scan's own stored `dns_monitor` records, printed
 * field by field, so the attribution the tunnel recorded is printed verbatim.
 */
class DnsAttributionReportTest {

    private fun scanOf(vararg findings: Finding) = scanWith(
        id = 1L, timestamp = 1711900800000, findings = findings.toList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = emptyList(),
    )

    private fun dns(domain: String, uid: Int, pkg: String?, reason: String? = null) = DnsEvent(
        timestamp = 1711900800000, domain = domain, appUid = uid, appName = pkg, isBlocked = false, reason = reason,
    )

    private fun reportWithDns(vararg events: DnsEvent) =
        reportText(scanOf(), telemetry = FakeTelemetry(mapOf("dns_monitor" to events.map { it.toFieldMap() })))

    @Test
    fun `a stored DNS record prints the querying app's uid and package`() {
        val text = reportWithDns(dns("graph.instagram.com", 10042, "com.instagram.android"))
        val block = text.substringAfter("${ReportFormatter.STORED_TELEMETRY_SECTION}: dns_monitor")
        assertTrue(block, block.contains("domain: graph.instagram.com"))
        assertTrue(block, block.contains("app_uid: 10042"))
        assertTrue(block, block.contains("source_package: com.instagram.android"))
    }

    @Test
    fun `a query made by the system resolver keeps the resolver's uid, not a placeholder`() {
        val text = reportWithDns(dns("mtalk.google.com", ConnectionOwnerResolver.DNS_RESOLVER_UID, null))
        assertTrue(text, text.contains("app_uid: ${ConnectionOwnerResolver.DNS_RESOLVER_UID}"))
        assertTrue(text, text.contains("source_package: null"))
    }

    @Test
    fun `the tunnel's reason is printed beside the domain it matched`() {
        val text = reportWithDns(dns("c2.evil.example", 10042, "com.evil.app", reason = "IOC_detect: c2.evil.example"))
        assertTrue(text, text.contains("reason: IOC_detect: c2.evil.example"))
    }

    @Test
    fun `a DNS-rule finding is grouped under the querying app, not unknown`() {
        val c2 = Finding(
            ruleId = "androdr-003", title = "Known C2 Domain Contacted", level = "critical",
            category = FindingCategory.APP_RISK, triggered = true,
            guidance = "INVESTIGATE -- device contacted a known C2 server",
            matchContext = mapOf("domain" to "c2.evil.example", "source_package" to "com.evil.app"),
        )

        val text = reportText(scanOf(c2), mode = ExportMode.FINDINGS_ONLY)
        val apps = text.substring(text.indexOf("APP RISKS"))

        assertTrue(apps, apps.contains("com.evil.app"))
        assertTrue("grouped under unknown: $apps", !apps.contains("unknown"))
    }
}
