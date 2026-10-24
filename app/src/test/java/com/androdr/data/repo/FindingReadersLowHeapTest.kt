package com.androdr.data.repo

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.DnsDropLog
import com.androdr.data.store.DnsDropState
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.ioc.Campaign
import com.androdr.reporting.ReportExporter
import com.androdr.reporting.ReportFiles
import com.androdr.scanner.ScanOrchestrator
import com.androdr.scanner.WriterFixture
import com.androdr.scanner.WriterFixture.Companion.APP_RULE
import com.androdr.scanner.WriterFixture.Companion.DNS_RULE
import com.androdr.scanner.WriterFixture.Companion.EVIL_APP
import com.androdr.scanner.WriterFixture.Companion.EVIL_DOMAIN
import com.androdr.ui.dashboard.DashboardViewModel
import com.androdr.util.AppVersion
import com.androdr.util.appVersion
import io.mockk.coVerify
import io.mockk.every
import io.mockk.coExcludeRecords
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
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
 * Review C1/I1 gate, under `lowHeapTest`'s 256 MB heap: after a 100,000-finding import, opening the
 * Dashboard ViewModel (the start screen), the History sheet and diff, and exporting the import's
 * report all complete with exact counts, because no reader holds the import's findings: the
 * Dashboard diffs live scans from SQL rule counts, the sheet counts in SQL, and the report streams
 * and folds. Runs only in `lowHeapTest`; `testDebugUnitTest` excludes `*LowHeap*`.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class FindingReadersLowHeapTest {
    private val w = WriterFixture(recordSql = false)
    private val dir: File = Files.createTempDirectory("low-heap-readers").toFile()
    private val findings = spyk(w.f.findings)

    @Before fun setUp() {
        // Keep the spy's call log small: only whole-scan reads are verified.
        coExcludeRecords { findings.forEachFinding(any(), any(), any()) }
        coExcludeRecords { findings.ruleSample(any(), any(), any()) }
        Dispatchers.setMain(UnconfinedTestDispatcher())
        mockkStatic("com.androdr.util.AppVersionKt")
        every { any<Context>().appVersion() } returns AppVersion("test", 1L)
    }

    @After fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
        w.close()
        dir.deleteRecursively()
    }

    private suspend fun liveScan(id: Long, vararg pkgs: String) {
        val s = w.writer.begin(w.scan(id), liveEvents = true)
        s.append("app_scanner", TelemetrySource.LIVE_SCAN, CAPTURED, pkgs.map { app(it) })
        s.finish()
    }

    private suspend fun bigImport(id: Long): ScanResult {
        val s = w.writer.begin(w.scan(id, TelemetrySource.INTRUSION_LOG_IMPORT), liveEvents = false)
        s.appendAll("dns_monitor", TelemetrySource.INTRUSION_LOG_IMPORT, WriterFixture.IMPORT_CAPTURED,
            (0 until FINDINGS).asSequence().map { dns(EVIL_DOMAIN, time = 1_000L + it, key = "dns $it") })
        return s.finish().scan
    }

    private fun repository() = ScanRepository(w.f.db.scanResultDao(), w.f.db.dnsEventDao(),
        w.f.db.forensicTimelineEventDao(), mockk(relaxed = true), w.repo, w.lock, w.f.db)

    private fun exporter() = ReportExporter(ApplicationProvider.getApplicationContext(), w.f.reader,
        mockk {
            every { campaigns() } returns listOf(Campaign("pegasus", "Pegasus"))
            every { ruleScopes() } returns emptyMap()
            every { ruleCategoryById() } returns emptyMap()
        }, ReportFiles(dir), findings)

    @Test
    fun `after a 100k-finding import the Dashboard, History and report stay bounded and exact`() = runBlocking {
        assertTrue("run through the lowHeapTest task (max heap ${Runtime.getRuntime().maxMemory() shr 20} MB)",
            Runtime.getRuntime().maxMemory() <= HEAP_CEILING)
        liveScan(1L, EVIL_APP, "com.ok")
        liveScan(2L, "com.ok")
        val import = bigImport(3L)
        assertEquals(FINDINGS, import.triggeredCount)

        // The Dashboard (start screen): the diff is the two newest live scans, in SQL.
        val vm = DashboardViewModel(
            orchestrator = mockk(relaxed = true), repository = repository(), findings = findings,
            indicatorDao = mockk(relaxed = true),
            iocDatabase = mockk { every { getAllBadPackages() } returns emptyList() },
            intelRefresher = mockk(relaxed = true), storageHealth = w.health,
            dnsDropLog = mockk<DnsDropLog> { every { state } returns flowOf(DnsDropState(0L, 0L)) },
            context = ApplicationProvider.getApplicationContext(),
        )
        val diff = vm.scanDiff.filterNotNull().first()
        assertEquals("the live scans' diff: the EVIL_APP finding resolved", 0, diff.newCount)
        assertEquals(1, diff.resolvedCount)
        assertEquals(listOf(APP_RULE), diff.resolvedFindings.map { it.ruleId })
        assertEquals("open alerts include the import's", FINDINGS, vm.currentFindings.filterNotNull()
            .first { it.openAlertCount > 0 }.openAlertCount)

        // History: the sheet's counts in SQL, and the diff of the import against its predecessor.
        val summary = exporter().summary(import)
        assertEquals(FINDINGS, summary.appIssues)
        assertEquals(0, summary.deviceIssues)
        val historyDiff = ScanOrchestrator.boundedDiff(findings, import, repository().previousOf(import)!!)
        assertEquals(FINDINGS, historyDiff.newCount)
        assertTrue(historyDiff.newFindings.size <= ScanOrchestrator.DIFF_DISPLAY_LIMIT)
        assertEquals(DNS_RULE, historyDiff.newFindings.first().ruleId)

        // The report streams and folds the import's findings.
        val file = File(dir, "report.txt")
        exporter().writeTo(file, import, includeLog = false)
        val text = file.readText()
        assertTrue(text.lines().first { "app issue(s)" in it }, text.contains("$FINDINGS app issue(s)"))

        coVerify(exactly = 0) { findings.findingsOf(3L, any()) }
        coVerify(exactly = 0) { findings.withFindings(import, any()) }
    }

    private companion object {
        const val FINDINGS = 100_000
        /** 256 MB plus slack for how the JVM reports `-Xmx`. */
        const val HEAP_CEILING = 280L shl 20
    }
}
