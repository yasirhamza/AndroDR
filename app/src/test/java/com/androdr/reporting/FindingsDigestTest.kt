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
        // The reference the formatter computes: the latest observation not after the import (review Minor B).
        val reference = hits.map { (it.evidence as Evidence.IocMatch).observedAt }.filter { it <= scanTime }.max()
        val digest = FindingsDigest(reference - CAMPAIGN_HIT_WINDOW_MS, scanTime, live = false)
        hits.forEach(digest::add)
        val f = digest.result()
        assertEquals(render(scan, FindingsView(hits, campaigns)),
            render(scan, FindingsView(f.findings, campaigns, counts = f.counts)))
    }

    /** Review Minor B: a hit exactly at the window start is recent; one millisecond earlier is old. */
    @Test
    fun `hits at the window edge fold into the bucket the verdict reads them in`() {
        val start = scanTime - CAMPAIGN_HIT_WINDOW_MS
        for (edge in listOf(start, start - 1)) {
            val hits = listOf(dns("a.example", edge), dns("a.example", start - 10 * day))
            val scan = scanWith(hits, id = 1L, timestamp = scanTime)
            val text = render(scan, folded(scan))
            assertEquals(render(scan, FindingsView(hits, campaigns)), text)
            val detected = edge == start
            assertEquals("$edge", detected, text.contains("Pegasus: DETECTED"))
            assertEquals("$edge", !detected, text.contains("Pegasus: earlier hit only"))
        }
    }

    /** Review Minor C: equally latest hits on two indicators name the same one, whatever the order. */
    @Test
    fun `a tie of the latest hit names the same indicator folded or not`() {
        val t = scanTime - day
        val hits = listOf(dns("b.example", t), dns("a.example", t - 5), dns("a.example", t))
        val scan = scanWith(hits, id = 1L, timestamp = scanTime)
        val text = render(scan, folded(scan))
        assertEquals(render(scan, FindingsView(hits, campaigns)), text)
        fun detected(t: String) = t.lines().single { "Pegasus: DETECTED" in it }
        assertTrue(detected(text), detected(text).contains("b.example"))
        assertEquals("the named hit does not depend on list order", detected(text),
            detected(render(scan, FindingsView(hits.reversed(), campaigns))))
    }

    /** Review I1-r: what an import's report never prints never splits a fold, so 1,000 distinct domains fold. */
    @Test
    fun `distinct domains fold where the report does not print them`() {
        fun ddns(i: Int) = Finding(ruleId = "androdr-070", title = "Dynamic DNS Domain", level = "medium",
            category = FindingCategory.APP_RISK, matchContext = mapOf("domain" to "h$i.duckdns.org",
                "source_package" to "com.app", "reason" to "", "timestamp" to "$i"))
        for (live in listOf(true, false)) {
            val digest = FindingsDigest(0L, scanTime, live)
            repeat(1_000) { digest.add(ddns(it)) }
            assertEquals("live=$live: no IOC-domain evidence, so no Blocked line and one entry", 1, digest.size)
        }
        // A live scan's IOC-domain finding prints its domain (the Blocked line): those stay distinct.
        val live = FindingsDigest(0L, scanTime, live = true)
        repeat(10) { live.add(dns("d$it.example", scanTime - day)) }
        assertEquals(10, live.size)
        val import = FindingsDigest(0L, scanTime, live = false)
        repeat(10) { import.add(dns("a.example", scanTime - day, pkg = "com.app").let { f ->
            f.copy(matchContext = f.matchContext + ("domain" to "d$it.example")) }) }
        assertEquals("an import never prints Blocked lines", 1, import.size)
    }

    /** Review I1-r: a folded entry keeps only the printed context, and per-rule text is interned. */
    @Test
    fun `an entry keeps only what the report prints, with shared per-rule text`() {
        val digest = FindingsDigest(0L, scanTime, live = false)
        // Decoded findings carry their own string instances, as the reader produces them.
        fun fresh(f: Finding) = f.copy(description = String(f.description.toCharArray()),
            remediation = f.remediation.map { String(it.toCharArray()) })
        digest.add(fresh(dns("a.example", 0L, pkg = "com.x")))
        digest.add(fresh(dns("a.example", 0L, pkg = "com.y")))
        val (x, y) = digest.result().findings
        assertEquals(mapOf("source_package" to "com.x"), x.matchContext)
        assertTrue("one description instance", x.description === y.description)
        assertTrue("one remediation list instance", x.remediation === y.remediation)
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
