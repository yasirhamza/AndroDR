package com.androdr.reporting

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.scanner.AppScanner
import com.androdr.scanner.ScanOrchestrator
import com.androdr.util.AppVersion
import com.androdr.util.appVersion
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Regression guard for #342 C4 (security L5). ReportExporter used to fetch
 * getEventsBySource("intrusion_log", 500) UNCONDITIONALLY, so EVERY report —
 * a live scan, or a historical scan from before any import — embedded up to 500
 * imported rows (wrong provenance, widened disclosure). The fetch is now scoped
 * by scan.id, so only the report FOR an import embeds its rows.
 *
 * The imported rows are stubbed to EXIST in the DB (unscoped query returns them)
 * so this test bites if the scoping is reverted: a live-scan report would then
 * embed them again.
 */
class ReportExporterScopeTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val context = mockk<Context>(relaxed = true)
    private val dnsEventDao = mockk<DnsEventDao>(relaxed = true)
    private val scanOrchestrator = mockk<ScanOrchestrator>(relaxed = true)
    private val appScanner = mockk<AppScanner>(relaxed = true)
    private val timelineDao = mockk<ForensicTimelineEventDao>(relaxed = true)
    private lateinit var exporter: ReportExporter

    private val importScanId = 1_000L
    private val liveScanId = 2_000L

    private fun importRow() = ForensicTimelineEvent(
        startTimestamp = 1_700_000_000_000L, source = "intrusion_log",
        category = "network_connect", description = "Connect: 9.9.9.9:853",
        scanResultId = importScanId, telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT,
    )

    @Before
    fun setUp() {
        mockkStatic(FileProvider::class)
        every { FileProvider.getUriForFile(any(), any(), any()) } returns mockk<Uri>(relaxed = true)
        mockkStatic("com.androdr.util.AppVersionKt")
        every { any<Context>().appVersion() } returns AppVersion("test", 1L)

        // The import's rows EXIST in the DB. The scoped query returns them only
        // for the import scan; the unscoped query (the reverted behavior) would
        // return them for any report.
        every { timelineDao.getEventsBySource("intrusion_log", any()) } returns flowOf(listOf(importRow()))
        every {
            timelineDao.getEventsBySourceForScan("intrusion_log", importScanId, any())
        } returns flowOf(listOf(importRow()))
        every {
            timelineDao.getEventsBySourceForScan("intrusion_log", liveScanId, any())
        } returns flowOf(emptyList())

        exporter = ReportExporter(context, dnsEventDao, scanOrchestrator, appScanner, timelineDao)
    }

    private fun scan(id: Long) = ScanResult(
        id = id, timestamp = id, findings = emptyList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0,
    )

    private suspend fun reportTextFor(scan: ScanResult): String {
        val cacheDir = tempFolder.newFolder("cache_${scan.id}")
        every { context.cacheDir } returns cacheDir
        exporter.export(scan)
        val reportsDir = File(cacheDir, "reports")
        val file = reportsDir.listFiles { f -> f.extension == "txt" }?.singleOrNull()
            ?: error("expected exactly one report file in $reportsDir")
        return file.readText()
    }

    @Test
    fun `live-scan report does not embed intrusion-log rows`() = runTest {
        val text = reportTextFor(scan(liveScanId))
        assertFalse("live-scan report must NOT contain the intrusion section", text.contains("INTRUSION LOG"))
        assertFalse(text.contains("Connect: 9.9.9.9:853"))
    }

    @Test
    fun `intrusion-log report embeds its own rows`() = runTest {
        val text = reportTextFor(scan(importScanId))
        assertTrue("intrusion-log report MUST contain the intrusion section", text.contains("INTRUSION LOG"))
        assertTrue(text.contains("Connect: 9.9.9.9:853"))
    }
}
