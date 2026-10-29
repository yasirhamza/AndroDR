package com.androdr.reporting

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.scanner.ChunkedScanWriter
import com.androdr.scanner.WriterFixture
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleParser
import com.androdr.util.AppVersion
import com.androdr.util.appVersion
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.nio.file.Files

/**
 * Review I1-r gate, under `lowHeapTest`'s 256 MB heap: report export of an import whose 100,000
 * findings are all distinct — a DDNS-style rule firing on 100,000 distinct subdomains — completes
 * with exact counts and lines. Nothing folds by the finding itself (every `matchContext["domain"]`
 * differs), so the bound comes from [FindingsDigest] keeping only what the report prints: an
 * import's report never prints a domain from `matchContext`, so the findings fold per app.
 * Also measures what one digest entry retains when every entry *is* a printed line (distinct IOC
 * indicators). Runs only in `lowHeapTest`; `testDebugUnitTest` excludes `*LowHeap*`.
 */
@RunWith(RobolectricTestRunner::class)
class ReportExportLowHeapTest {
    private val w = WriterFixture(recordSql = false)
    private val dir: File = Files.createTempDirectory("low-heap-report").toFile()

    @Before fun setUp() {
        mockkStatic("com.androdr.util.AppVersionKt")
        every { any<Context>().appVersion() } returns AppVersion("test", 1L)
    }

    @After fun tearDown() {
        unmockkAll()
        w.close()
        dir.deleteRecursively()
    }

    private val ddnsRule = SigmaRuleParser.parse(
        """
            title: DNS query to dynamic DNS provider
            id: androdr-t-ddns
            status: experimental
            description: A DNS query was made to a known dynamic DNS provider.
            category: incident
            logsource:
                product: androdr
                service: dns_monitor
            detection:
                selection:
                    domain|endswith: ".duckdns.org"
                condition: selection
            level: medium
            tags:
                - attack.t1481
            display:
                category: app_risk
                triggered_title: "Dynamic DNS Domain"
            remediation:
                - "A connection to a dynamic DNS service was detected."
        """.trimIndent()
    )!!

    @Test
    fun `report export of 100k distinct-domain DDNS findings stays bounded and exact`() = runBlocking {
        assertTrue("run through the lowHeapTest task", Runtime.getRuntime().maxMemory() <= HEAP_CEILING)
        val engine = SigmaRuleEngine(mockk(relaxed = true)).apply { setRemoteRules(listOf(ddnsRule)) }
        val writer = ChunkedScanWriter(engine, w.store, w.repo, w.f.findings, w.preflight, w.health)
        val s = writer.begin(w.scan(7L, TelemetrySource.INTRUSION_LOG_IMPORT), liveEvents = false)
        s.appendAll("dns_monitor", TelemetrySource.INTRUSION_LOG_IMPORT, WriterFixture.IMPORT_CAPTURED,
            (0 until FINDINGS).asSequence().map { dns("h$it.duckdns.org", time = 1_000L + it, key = "dns $it") })
        val scan = s.finish().scan
        assertEquals(FINDINGS, scan.triggeredCount)

        val inputs = mockk<ReportInputs> {
            every { campaigns() } returns emptyList()
            every { ruleScopes() } returns emptyMap()
            every { ruleCategoryById() } returns emptyMap()
        }
        val view = FindingsView.of(scan, inputs, w.f.findings, w.f.reader)
        assertEquals("100k distinct findings fold to one entry per app", 1, view.findings.size)
        assertEquals(FINDINGS, view.countOf(view.findings))

        val file = File(dir, "report.txt")
        ReportExporter(ApplicationProvider.getApplicationContext(), w.f.reader, inputs, ReportFiles(dir), w.f.findings)
            .writeTo(file, scan, includeLog = false)
        val text = file.readText()
        assertTrue(text, text.contains("$FINDINGS app issue(s) and 0 device setting(s) found."))
        assertTrue(text, text.contains("  1 application(s) flagged"))
        assertTrue(text, text.contains("     Reasons : Dynamic DNS Domain\n"))
        assertTrue("an import's report prints no Blocked line", !text.contains("Blocked :"))
    }

    /**
     * When every entry is a distinct printed line (100k distinct IOC indicators), what one entry
     * retains beyond its printed text: measured, and bounded at [ENTRY_BOUND_BYTES].
     */
    @Test
    fun `one digest entry of a distinct printed line retains a bounded size`() {
        assertTrue("run through the lowHeapTest task", Runtime.getRuntime().maxMemory() <= HEAP_CEILING)
        // Long per-rule texts, decoded fresh per finding as the reader does: interning must share them.
        val description = "A DNS query matched a threat-intelligence indicator. ".repeat(20)
        val remediation = "Remove the app that made the query and reset its credentials. ".repeat(5)
        fun fresh(text: String) = String(text.toCharArray())
        fun finding(i: Int) = Finding(ruleId = fresh("androdr-003"), title = fresh("Malicious domain"),
            description = fresh(description), level = "high", category = FindingCategory.APP_RISK,
            tags = listOf(fresh("attack.t1437")), remediation = listOf(fresh(remediation)),
            guidance = fresh("CRITICAL: remove the app"),
            evidence = Evidence.IocMatch("d$i.example", "domain", fresh("feed"), family = fresh("Pegasus"),
                observedAt = 1_000L + i),
            matchContext = mapOf("domain" to "d$i.example", "source_package" to "com.app${i % 50}",
                "timestamp" to "${1_000L + i}", "app_uid" to "${i % 9}", "reason" to "IOC: x"))

        val baseline = usedAfterGc()
        val digest = FindingsDigest(0L, Long.MAX_VALUE, live = true)
        for (i in 0 until ENTRIES) digest.add(finding(i))
        val used = usedAfterGc() - baseline
        assertEquals(ENTRIES, digest.size)
        val perEntry = used / ENTRIES
        println("FindingsDigest retained ${used shr 10} KiB for $ENTRIES distinct entries: $perEntry B/entry")
        assertTrue("$perEntry B per entry", perEntry <= ENTRY_BOUND_BYTES)
        assertEquals(ENTRIES, digest.result().findings.size)
    }

    private fun usedAfterGc(): Long {
        repeat(3) { System.gc(); Thread.sleep(50) }
        val r = Runtime.getRuntime()
        return r.totalMemory() - r.freeMemory()
    }

    private companion object {
        const val FINDINGS = 100_000
        const val ENTRIES = 100_000
        /** Per entry: the printed text (indicator, domain, package) and the compact finding around it. */
        const val ENTRY_BOUND_BYTES = 1_200L
        const val HEAP_CEILING = 280L shl 20
    }
}
