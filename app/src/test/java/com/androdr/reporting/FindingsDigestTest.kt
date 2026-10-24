package com.androdr.reporting

import com.androdr.data.model.ScanWithFindings
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.scanWith
import com.androdr.ioc.Campaign
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.StringWriter

/**
 * Review I1: the report folds findings that would print the same ([FindingsDigest]), so a 100k-finding
 * import is reported without being held. The folded report must read exactly like the report over
 * every finding: same verdict, counts, campaign rows (window buckets included), per-app groups,
 * DNS rows and Blocked lines.
 */
class FindingsDigestTest {

    private val day = 24L * 60 * 60 * 1000
    private val scanTime = 1_800_000_000_000L
    private val campaigns = listOf(Campaign("pegasus", "Pegasus"))

    private fun dns(domain: String, observedAt: Long, pkg: String = "com.app", reason: String = "") = Finding(
        ruleId = "androdr-003", title = "Malicious domain: $domain", description = "d", level = "high",
        category = FindingCategory.APP_RISK, tags = listOf("attack.t1437"), remediation = listOf("block it"),
        guidance = "CRITICAL: act", evidence = Evidence.IocMatch(domain, "domain", "feed", family = "Pegasus",
            campaign = "pegasus", observedAt = observedAt),
        matchContext = mapOf("domain" to domain, "source_package" to pkg, "reason" to reason,
            "timestamp" to "$observedAt", "app_uid" to "${observedAt % 7}"),
    )

    private fun device(title: String, triggered: Boolean = true) = Finding(ruleId = "androdr-04$title",
        title = "Check $title", level = "medium", category = FindingCategory.DEVICE_POSTURE, triggered = triggered)

    private fun render(scan: ScanWithFindings, view: FindingsView): String = runBlocking {
        val out = StringWriter()
        ReportFormatter.writeScanReport(out, scan.scan, view, emptyList(), FakeTelemetry(), ExportMode.FINDINGS_ONLY,
            "test")
        out.toString().lines().filterNot { it.startsWith("  Generated : ") }.joinToString("\n")
    }

    private fun folded(scan: ScanWithFindings): FindingsView {
        val digest = FindingsDigest(scanTime - CAMPAIGN_HIT_WINDOW_MS, scanTime)
        scan.findings.forEach(digest::add)
        val f = digest.result()
        return FindingsView(f.findings, campaigns, counts = f.counts)
    }

    @Test
    fun `the folded report reads exactly like the report over every finding`() {
        // 3,000 DNS hits: two domains, old, recent and future-dated observations, two apps.
        val hits = (0 until 3_000).map { i ->
            val time = when (i % 4) {
                0 -> scanTime - 45 * day + i
                1 -> scanTime - 2 * day + i
                2 -> scanTime + day + i
                else -> 0L
            }
            dns(if (i % 2 == 0) "a.example" else "b.example", time, pkg = if (i % 3 == 0) "com.x" else "com.y")
        }
        val all = listOf(device("1"), device("2", triggered = false)) + hits
        val scan = scanWith(all, id = 1L, timestamp = scanTime)
        val view = folded(scan)
        assertTrue("folding bounds the entries", view.findings.size < 40)
        assertEquals(render(scan, FindingsView(all, campaigns)), render(scan, view))
    }

    /**
     * An IOC hit with no observation time counts at the reference time (recent), so a fold that kept
     * only the latest observed hit (an old one) would turn DETECTED into "earlier hit only".
     */
    @Test
    fun `a hit with no observation time is not folded into an older observed hit`() {
        val hits = listOf(dns("a.example", 0L), dns("a.example", scanTime - 45 * day), dns("a.example", 0L))
        val scan = scanWith(hits, id = 1L, timestamp = scanTime)
        val text = render(scan, folded(scan))
        assertTrue(text, text.contains("Pegasus: DETECTED"))
        assertEquals(render(scan, FindingsView(hits, campaigns)), text)
    }

    @Test
    fun `the folded report of an import keeps the campaign window`() {
        val hits = (0 until 500).map { i -> dns("a.example", scanTime - (if (i % 2 == 0) 40 else 5) * day - i) }
        val scan = scanWith(hits, id = 1L, timestamp = scanTime, source = TelemetrySource.INTRUSION_LOG_IMPORT)
        val digest = FindingsDigest(scanTime - 5 * day - CAMPAIGN_HIT_WINDOW_MS, scanTime)
        hits.forEach(digest::add)
        val f = digest.result()
        assertEquals(render(scan, FindingsView(hits, campaigns)),
            render(scan, FindingsView(f.findings, campaigns, counts = f.counts)))
    }

    @Test
    fun `identical device findings fold into one line with how many it stands for`() {
        val all = listOf(device("1"), device("1"), device("1"))
        val scan = scanWith(all, id = 1L, timestamp = scanTime)
        val text = render(scan, folded(scan))
        assertTrue(text, text.contains("3 of 3 checks triggered"))
        assertTrue(text, text.contains("Check 1  (3 times)"))
        assertTrue(text, text.contains("3 device setting(s)"))
    }
}
