package com.androdr.reporting

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.ioc.Campaign
import com.androdr.sigma.StoreRecord
import com.androdr.util.AppVersion
import com.androdr.util.appVersion
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * R1 (spec §7): a report's telemetry sections read only that scan's own stored observations, and
 * when a scan has no (or only some) telemetry, the report says why. Before Phase B every report
 * printed `ScanOrchestrator`'s last-scan caches, so exporting an older scan showed the newest
 * scan's apps, and an import's report could show the live tunnel's DNS. Runs end to end through
 * [ReportExporter], the one report path, over a real in-memory store.
 */
@RunWith(RobolectricTestRunner::class)
class ReportProvenanceTest {

    @get:Rule val tmp = TemporaryFolder()

    private val f = StoreFixture()
    private val context = mockk<Context>(relaxed = true)
    private lateinit var reportsDir: File
    private lateinit var exporter: ReportExporter

    @Before
    fun setUp() {
        mockkStatic(FileProvider::class)
        every { FileProvider.getUriForFile(any(), any(), any()) } returns mockk<Uri>(relaxed = true)
        mockkStatic("com.androdr.util.AppVersionKt")
        every { any<Context>().appVersion() } returns AppVersion("test", 1L)
        reportsDir = tmp.newFolder("reports")
        exporter = ReportExporter(
            context = context, telemetryReader = f.reader,
            reportInputs = mockk {
                // A DNS-only campaign reads [OK] only while its detector's scope reaches the formatter.
                every { campaigns() } returns listOf(Campaign("pegasus", "Pegasus", detectedBy = listOf("dns_monitor")))
                every { ruleCategoryById() } returns emptyMap()
                every { ruleScopes() } returns mapOf("androdr-003" to RuleScope("dns_monitor", emptySet(), true))
            },
            reportFiles = ReportFiles(reportsDir),
            findings = f.findings,
        )
    }

    @After
    fun tearDown() {
        unmockkAll()
        f.close()
    }

    private suspend fun scan(
        id: Long,
        source: TelemetrySource = TelemetrySource.LIVE_SCAN,
        telemetryState: TelemetryState = TelemetryState.STORED,
    ): ScanResult {
        val s = ScanResult(
            id = id, timestamp = id, bugReportFindings = emptyList(),
            riskySideloadCount = 0, knownMalwareCount = 0, source = source, state = ScanState.IN_PROGRESS,
            telemetryState = telemetryState,
        )
        f.db.scanResultDao().insert(s)
        return s
    }

    private fun complete(id: Long) = f.setState(id, ScanState.COMPLETE)

    private suspend fun report(scan: ScanResult, mode: ExportMode = ExportMode.BOTH): String {
        reportsDir.listFiles()?.forEach { it.delete() }
        exporter.export(scan.copy(state = ScanState.COMPLETE), mode)
        val file = reportsDir.listFiles { x -> x.extension == "txt" }?.singleOrNull()
            ?: error("expected exactly one report file in $reportsDir")
        return file.readText()
    }

    @Test
    fun `each scan's report shows that scan's packages only`() = runBlocking {
        val a = scan(1_000L)
        f.persist(a.id, "app_scanner", listOf(app("com.scan.a")))
        complete(a.id)
        val b = scan(2_000L)
        f.persist(b.id, "app_scanner", listOf(app("com.scan.b")))
        complete(b.id)

        val textA = report(a)
        assertTrue(textA, textA.contains("package_name: com.scan.a"))
        assertFalse("scan A's report shows scan B's app", textA.contains("com.scan.b"))
        val textB = report(b)
        assertTrue(textB, textB.contains("package_name: com.scan.b"))
        assertFalse("scan B's report shows scan A's app", textB.contains("com.scan.a"))
    }

    @Test
    fun `an import's report shows only its own services`() = runBlocking {
        val live = scan(1_000L)
        f.persist(live.id, "app_scanner", listOf(app("com.live.app")))
        f.persist(live.id, "dns_monitor", listOf(dns("live-tunnel.example")))
        complete(live.id)
        val import = scan(2_000L, source = TelemetrySource.INTRUSION_LOG_IMPORT)
        f.persist(
            import.id, "dns_monitor", listOf(dns("imported.example")), source = TelemetrySource.INTRUSION_LOG_IMPORT,
        )
        complete(import.id)

        val text = report(import)
        assertTrue(text, text.contains("${ReportFormatter.STORED_TELEMETRY_SECTION}: dns_monitor (1 record(s))"))
        assertTrue(text, text.contains("domain: imported.example"))
        assertFalse("the import shows the live scan's app section", text.contains("app_scanner"))
        assertFalse("the import shows the live tunnel's DNS", text.contains("live-tunnel.example"))
        assertFalse(text.contains("com.live.app"))
    }

    @Test
    fun `PARTIAL_RETENTION, NONE and FAILED each print their own line`() = runBlocking {
        val lines = mapOf(
            TelemetryState.PARTIAL_RETENTION to ReportFormatter.TELEMETRY_PARTIAL,
            TelemetryState.NONE to ReportFormatter.TELEMETRY_NONE,
            TelemetryState.FAILED to ReportFormatter.TELEMETRY_FAILED,
        )
        assertEquals("three distinct lines", 3, lines.values.toSet().size)
        var id = 1_000L
        for ((state, line) in lines) {
            val s = scan(id++, telemetryState = state)
            if (state == TelemetryState.PARTIAL_RETENTION) f.persist(s.id, "app_scanner", listOf(app("com.kept")))
            complete(s.id)
            val text = report(s)
            assertTrue("$state: $text", text.lines().any { it.trim().startsWith(line) })
            (lines.values - line).forEach { other -> assertFalse("$state prints $other", text.contains(other)) }
        }
        val stored = scan(id, telemetryState = TelemetryState.STORED)
        complete(stored.id)
        val text = report(stored)
        lines.values.forEach { assertFalse("STORED prints $it", text.contains(it)) }
    }

    @Test
    fun `a FAILED scan with stored records says how many were stored, never that nothing was saved`() =
        runBlocking {
            val s = scan(1_000L, telemetryState = TelemetryState.FAILED)
            f.persist(s.id, "app_scanner", listOf(app("com.kept.a"), app("com.kept.b")))
            complete(s.id)
            val text = report(s)
            assertTrue(text, text.contains(
                "${ReportFormatter.TELEMETRY_FAILED_PARTWAY} 2 record(s) were stored before it failed;"))
            assertFalse(text, text.contains(ReportFormatter.TELEMETRY_FAILED))
            assertTrue(text, text.contains("package_name: com.kept.a"))
            assertFalse(exporter.summary(s.copy(state = ScanState.COMPLETE)).lines()
                .any { it.contains(ReportFormatter.TELEMETRY_FAILED) })
            assertTrue("a partly stored scan's app count is not the number scanned",
                text.contains("Apps scanned: N/A (only part of this scan's telemetry is stored)"))
        }

    @Test
    fun `an import's DNS section carries no tunnel verdict and no note about one`() = runBlocking {
        val import = scan(1_000L, source = TelemetrySource.INTRUSION_LOG_IMPORT)
        val record = StoreRecord(
            mapOf("domain" to "c2.example", "app_uid" to 10_001, "source_package" to "com.example",
                "timestamp" to 1_729_600_000_000L, "resolved_ips" to listOf("1.2.3.4")),
        )
        f.persist(import.id, "dns_monitor", listOf(record), source = TelemetrySource.INTRUSION_LOG_IMPORT)
        complete(import.id)
        val text = report(import)
        val dnsSection = text.substringAfter("${ReportFormatter.STORED_TELEMETRY_SECTION}: dns_monitor")
        assertTrue(text, dnsSection.contains("domain: c2.example"))
        assertFalse(text, dnsSection.contains("is_blocked"))
        assertFalse(text, dnsSection.contains("reason:"))
        assertFalse(text, text.contains(ReportFormatter.DNS_LIVE_NOTE))
        assertFalse(text, text.contains("Imported queries"))

        val live = scan(2_000L)
        f.persist(live.id, "dns_monitor", listOf(dns("live.example")))
        complete(live.id)
        val liveText = report(live)
        assertTrue(liveText, liveText.contains(ReportFormatter.DNS_LIVE_NOTE))
        assertTrue(liveText, liveText.contains("is_blocked: false"))
    }

    @Test
    fun `a live scan's report never shows an import's records`() = runBlocking {
        val import = scan(1_000L, source = TelemetrySource.INTRUSION_LOG_IMPORT)
        f.persist(import.id, "dns_monitor", listOf(dns("imported-only.example")),
            source = TelemetrySource.INTRUSION_LOG_IMPORT)
        complete(import.id)
        val live = scan(2_000L)
        f.persist(live.id, "app_scanner", listOf(app("com.live.app")))
        complete(live.id)
        val text = report(live)
        assertTrue(text, text.contains("package_name: com.live.app"))
        assertFalse(text, text.contains("imported-only.example"))
        assertFalse(text, text.contains("${ReportFormatter.STORED_TELEMETRY_SECTION}: dns_monitor"))
    }

    @Test
    fun `an intrusion-log import's connection and security records render`() = runBlocking {
        val import = scan(1_000L, source = TelemetrySource.INTRUSION_LOG_IMPORT)
        val src = TelemetrySource.INTRUSION_LOG_IMPORT
        f.persist(import.id, "network_monitor", listOf(com.androdr.sigma.StoreRecord(
            mapOf("destination_ip" to "8.8.8.8", "destination_port" to 853, "app_name" to "com.samsung.x"))),
            source = src)
        f.persist(import.id, "security_log", listOf(com.androdr.sigma.StoreRecord(
            mapOf("tag_name" to "adb_shell_cmd", "security_data" to "ls"))), source = src)
        complete(import.id)
        val text = report(import)
        assertTrue(text, text.contains("${ReportFormatter.STORED_TELEMETRY_SECTION}: network_monitor (1 record(s))"))
        assertTrue(text, text.contains("destination_ip: 8.8.8.8"))
        assertTrue(text, text.contains("${ReportFormatter.STORED_TELEMETRY_SECTION}: security_log (1 record(s))"))
        assertTrue(text, text.contains("tag_name: adb_shell_cmd"))
    }

    @Test
    fun `the harness report leaves the app log out, the shared export keeps it`() = runBlocking {
        exporter.logSource = { listOf("LOG-LINE-NAMING /data/local/tmp/.raptor") }
        val a = scan(1_000L)
        complete(a.id)
        val harness = File(tmp.root, "androdr_last_report.txt")
        exporter.writeTo(harness, a.copy(state = ScanState.COMPLETE), includeLog = false)
        assertFalse(harness.readText().contains("LOG-LINE-NAMING"))
        assertTrue(report(a).contains("LOG-LINE-NAMING"))
    }

    @Test
    fun `a findings-only report carries no telemetry records`() = runBlocking {
        val a = scan(1_000L)
        f.persist(a.id, "app_scanner", listOf(app("com.scan.a")))
        complete(a.id)
        val text = report(a, ExportMode.FINDINGS_ONLY)
        assertFalse(text, text.contains("package_name: com.scan.a"))
        assertFalse(text, text.contains(ReportFormatter.STORED_TELEMETRY_SECTION))
    }

    @Test
    fun `export forwards the loaded rules' scopes to the campaign rows`() = runBlocking {
        val a = scan(1_000L)
        complete(a.id)
        val text = report(a)
        assertTrue(text, text.contains("  [OK]  Pegasus: not detected"))
    }

    @Test
    fun `the History summary and the export estimate count only this scan's records`() = runBlocking {
        val a = scan(1_000L)
        f.persist(a.id, "app_scanner", listOf(app("com.a1"), app("com.a2")))
        f.persist(a.id, "dns_monitor", listOf(dns("a.example")))
        complete(a.id)
        val b = scan(2_000L)
        f.persist(b.id, "app_scanner", listOf(app("com.b1"), app("com.b2"), app("com.b3")))
        complete(b.id)

        val summary = exporter.summary(a.copy(state = ScanState.COMPLETE))
        assertEquals(listOf("app_scanner" to 2, "dns_monitor" to 1), summary.services.map { it.service to it.records })
        assertTrue(summary.lines().joinToString("\n"), summary.lines().any { "3 record(s)" in it })

        val estimate = exporter.exportEstimate(a.copy(state = ScanState.COMPLETE))
        assertEquals(3L, estimate.records)
        assertTrue(estimate.bytes > 0)
        assertEquals(listOf("installed apps", "DNS lookups"), estimate.categories)
    }

    @Test
    fun `stale report files are removed before an export`() = runBlocking {
        val stale = File(reportsDir, "androdr_report_old.txt").apply {
            writeText("old")
            setLastModified(System.currentTimeMillis() - ReportFiles.STALE_AFTER_MS - 60_000L)
        }
        val a = scan(1_000L)
        complete(a.id)
        exporter.export(a.copy(state = ScanState.COMPLETE))
        assertFalse("a stale export outlived the next export", stale.exists())
    }
}
