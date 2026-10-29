package com.androdr.ui.history

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.ScanRepository
import com.androdr.data.store.CanonicalJson
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.reporting.ReportExporter
import com.androdr.reporting.ReportFiles
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.io.StringWriter
import java.io.Writer
import java.util.zip.GZIPInputStream

/**
 * "Export telemetry (JSONL)" (spec §7, §8.2): [com.androdr.data.store.TelemetryReader.exportJsonl]
 * streams one envelope per observation, with the envelope keys storage stripped restored, an
 * unreadable body still gets a line, the export is gzip in `cache/reports/` with stale files removed
 * first, and only a COMPLETE scan is exported.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class TelemetryExportTest {
    @get:Rule val tmp = TemporaryFolder()

    private val f = StoreFixture()
    private lateinit var reportsDir: File
    private lateinit var exporter: ReportExporter

    @Before fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        mockkStatic(FileProvider::class)
        every { FileProvider.getUriForFile(any(), any(), any()) } returns mockk<Uri>(relaxed = true)
        reportsDir = tmp.newFolder("reports")
        exporter = ReportExporter(
            context = mockk<Context>(relaxed = true), telemetryReader = f.reader, reportInputs = mockk(),
            reportFiles = ReportFiles(reportsDir), findings = f.findings,
        )
    }

    @After fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
        f.close()
    }

    private fun lines(text: String): List<Map<String, Any?>> =
        text.lines().filter { it.isNotEmpty() }.map { CanonicalJson.parse(it) ?: error("not one JSON object: $it") }

    private suspend fun export(scanId: Long): List<Map<String, Any?>> =
        StringWriter().also { f.reader.exportJsonl(scanId, it) }.toString().let(::lines)

    @Test
    fun `each observation of the scan becomes one envelope, and no other scan's`() = runBlocking {
        f.scan(1L)
        f.persist(1L, "app_scanner", listOf(app("com.a"), app("com.b")))
        f.persist(1L, "dns_monitor", listOf(dns("a.example"), dns("b.example"), dns("c.example")))
        f.setState(1L, ScanState.COMPLETE)
        f.scan(2L)
        f.persist(2L, "app_scanner", listOf(app("com.other")))
        f.setState(2L, ScanState.COMPLETE)

        val out = export(1L)
        assertEquals(5, out.size)
        assertEquals(listOf("app_scanner" to 0, "app_scanner" to 1, "dns_monitor" to 0, "dns_monitor" to 1,
            "dns_monitor" to 2), out.map { it["service"] to (it["ordinal"] as Number).toInt() })
        assertTrue(out.all { (it["scan_id"] as Number).toLong() == 1L })
        assertEquals(listOf("com.a", "com.b"), out.take(2).map { (it["fields"] as Map<*, *>)["package_name"] })
        assertEquals(1_729_600_000_000L, (out[2]["event_time"] as Number).toLong())
        assertNull(out[0]["event_time"])
    }

    @Test
    fun `the envelope keys storage stripped are restored in each line`() = runBlocking {
        f.scan(1L)
        f.persist(1L, "app_scanner", listOf(app("com.a")), capturedAt = CAPTURED)
        f.setState(1L, ScanState.COMPLETE)
        assertEquals("storage stripped source and captured_at", 1L,
            f.count("SELECT COUNT(*) FROM scan_record WHERE strippedKeys <> 0"))

        val line = export(1L).single()
        val fields = line["fields"] as Map<*, *>
        assertEquals(TelemetrySource.LIVE_SCAN.name, fields["source"])
        assertEquals(CAPTURED, fields["captured_at"])
        assertEquals(TelemetrySource.LIVE_SCAN.name, line["source"])
        assertEquals(CAPTURED, line["captured_at"])
        assertEquals(false, line["unreadable"])
    }

    @Test
    fun `an unreadable body still gets a line that says so`() = runBlocking {
        f.scan(1L)
        f.persist(1L, "dns_monitor", listOf(dns("a.example"), dns("b.example")))
        f.setState(1L, ScanState.COMPLETE)
        f.db.openHelper.writableDatabase.execSQL("UPDATE record_body SET body = X'00'")

        val out = export(1L)
        assertEquals(2, out.size)
        assertTrue(out.all { it["unreadable"] == true && it.containsKey("fields") && it["fields"] == null })
    }

    @Test
    fun `a device-controlled line separator or bidi override cannot break or disguise a line`() = runBlocking {
        f.scan(1L)
        f.persist(1L, "app_scanner", listOf(app("com.a {\"x\":1}‮")))
        f.setState(1L, ScanState.COMPLETE)
        val text = StringWriter().also { f.reader.exportJsonl(1L, it) }.toString()
        assertFalse(text.contains(' ') || text.contains('‮'))
        assertTrue(text, text.contains("\\u2028") && text.contains("\\u202E"))
        assertEquals("com.a {\"x\":1}‮", (lines(text).single()["fields"] as Map<*, *>)["package_name"])
    }

    @Test
    fun `the export streams - the writer gets lines before the reader's last page is read`() = runBlocking {
        f.scan(1L)
        f.persist(1L, "app_scanner", (0 until 1_200).map { app("com.p$it") })
        f.setState(1L, ScanState.COMPLETE)
        fun pageReads() = synchronized(f.sql) { f.sql.count { it.contains("o.ordinal > ?") } }
        f.sql.clear()
        var pagesAtFirstWrite = -1
        val sink = object : Writer() {
            override fun write(cbuf: CharArray, off: Int, len: Int) {
                if (pagesAtFirstWrite < 0) pagesAtFirstWrite = pageReads()
            }
            override fun flush() = Unit
            override fun close() = Unit
        }
        assertEquals(1_200L, f.reader.exportJsonl(1L, sink))
        val total = pageReads()
        assertEquals("1,200 records read in pages of 500", 3, total)
        assertEquals("the first line was written after the first page, before the rest were read", 1,
            pagesAtFirstWrite)
    }

    @Test
    fun `the export is gzip JSONL in cache reports, and stale files there are removed first`() = runBlocking {
        val stale = File(reportsDir, "androdr_report_old.txt").apply {
            writeText("old")
            setLastModified(System.currentTimeMillis() - ReportFiles.STALE_AFTER_MS - 60_000L)
        }
        val fresh = File(reportsDir, "androdr_report_new.txt").apply { writeText("new") }
        f.scan(1L)
        f.persist(1L, "app_scanner", listOf(app("com.a"), app("com.b")))
        f.setState(1L, ScanState.COMPLETE)
        val scan = ScanResult(id = 1L, timestamp = 1L, bugReportFindings = emptyList(), riskySideloadCount = 0,
            knownMalwareCount = 0, state = ScanState.COMPLETE)

        exporter.exportTelemetry(scan)

        assertFalse("a stale export outlived the next export", stale.exists())
        assertTrue("a file younger than an hour is kept", fresh.exists())
        val gz = reportsDir.listFiles { x -> x.name.endsWith(".jsonl.gz") }?.singleOrNull()
            ?: error("expected one .jsonl.gz in ${reportsDir.list()?.toList()}")
        val text = GZIPInputStream(gz.inputStream()).bufferedReader().use { it.readText() }
        assertEquals(listOf("com.a", "com.b"), lines(text).map { (it["fields"] as Map<*, *>)["package_name"] })
        assertTrue("no partial file left", reportsDir.listFiles { x -> x.name.endsWith(".part") }.isNullOrEmpty())
    }

    @Test
    fun `the JSONL dialog states the record count, the size and the sensitive categories`() {
        val text = com.androdr.reporting.ExportEstimate(3, 2_048, listOf("installed apps", "DNS lookups")).jsonlText()
        assertTrue(text, text.contains("3 telemetry record(s)"))
        assertTrue(text, text.contains("2.0 KB"))
        assertTrue(text, text.contains("installed apps, DNS lookups"))
        assertTrue(text, text.contains("share it only with someone you trust"))
        assertTrue(com.androdr.reporting.ExportEstimate.NONE.jsonlText().contains("no stored telemetry"))
    }

    private fun vm(exporter: ReportExporter) = HistoryViewModel(
        repository = mockk<ScanRepository> {
            every { pagedScans() } returns flowOf(androidx.paging.PagingData.empty())
            every { hasScans } returns flowOf(true)
        },
        reportExporter = exporter,
        findings = mockk(relaxed = true),
        scanLock = com.androdr.data.repo.ScanLock(),
    )

    private val completeScan = ScanResult(id = 7L, timestamp = 7L, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, state = ScanState.COMPLETE)

    @Test
    fun `History shares a COMPLETE scan's telemetry export as gzip`() {
        val uri = mockk<Uri>()
        val exp = mockk<ReportExporter> {
            coEvery { exportTelemetry(completeScan) } returns uri
            coEvery { export(any(), any()) } returns uri
        }
        val vm = vm(exp)
        vm.exportTelemetry(completeScan)
        assertEquals(uri, vm.shareUri.value)
        assertEquals("application/gzip", vm.shareMimeType.value)
        vm.onShareConsumed()
        vm.exportReport(completeScan.copy(id = 8L))
        assertEquals("text/plain", vm.shareMimeType.value)
    }

    @Test
    fun `History never exports telemetry of a scan that is not COMPLETE`() {
        val exp = mockk<ReportExporter>(relaxed = true)
        val vm = vm(exp)
        for (state in listOf(ScanState.IN_PROGRESS, ScanState.DELETING)) {
            vm.exportTelemetry(completeScan.copy(state = state))
        }
        coVerify(exactly = 0) { exp.exportTelemetry(any()) }
        assertNull(vm.shareUri.value)
    }

    @Test
    fun `a failed telemetry export is surfaced, never thrown`() {
        val exp = mockk<ReportExporter> { coEvery { exportTelemetry(any()) } throws java.io.IOException("disk full") }
        val vm = vm(exp)
        vm.exportTelemetry(completeScan)
        assertTrue(vm.exportFailed.value)
        assertFalse(vm.exporting.value)
        assertNull(vm.shareUri.value)
    }
}
