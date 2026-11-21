package com.androdr.ui.bugreport

import android.net.Uri
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetryState
import com.androdr.reporting.ExportEstimate
import com.androdr.reporting.ExportMode
import com.androdr.reporting.ReportExporter
import com.androdr.scanner.IntrusionLogAnalysisResult
import com.androdr.scanner.IntrusionLogStats
import com.androdr.scanner.ScanOrchestrator
import com.androdr.scanner.WriteResult
import com.androdr.data.store.Preflight
import com.androdr.scanner.ImportPreflight
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.IOException

/**
 * The import screen's Export used to write the full report (every stored record) with no dialog and
 * no progress: on a large intrusion log the button went inactive for a minute and nothing else
 * showed. It now goes through the same export dialog as History (size estimate, findings only), and
 * a failed export is reported instead of crashing.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BugReportExportTest {

    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private val scan = ScanResult(
        id = 7L, timestamp = 1L, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0,
    )
    private val stats = IntrusionLogStats(
        dnsEventCount = 3, connectEventCount = 1, securityEventCount = 2, duplicatesCollapsed = 0,
        malformedLines = 0, earliestEventMs = null, latestEventMs = null, truncated = false,
    )

    private fun importedVm(exporter: ReportExporter): BugReportViewModel {
        val orchestrator = mockk<ScanOrchestrator> {
            coEvery { analyzeArtifact(any()) } returns ScanOrchestrator.ArtifactAnalysis.IntrusionLog(
                IntrusionLogAnalysisResult(stats, write = WriteResult(4, 2, 1, TelemetryState.STORED, scan)),
            )
        }
        val vm = BugReportViewModel(
            orchestrator,
            mockk<ImportPreflight> { coEvery { check(any()) } returns Preflight.Ok },
            exporter, mockk(relaxed = true),
        )
        vm.onFilePicked(mockk<Uri>(relaxed = true))
        return vm
    }

    @Test
    fun `export writes the mode chosen in the dialog`() = runTest {
        val uri = mockk<Uri>()
        val exporter = mockk<ReportExporter> { coEvery { export(scan, ExportMode.FINDINGS_ONLY) } returns uri }
        val vm = importedVm(exporter)

        vm.exportReport(ExportMode.FINDINGS_ONLY)

        coVerify(exactly = 1) { exporter.export(scan, ExportMode.FINDINGS_ONLY) }
        assertEquals(uri, vm.shareUri.value)
    }

    @Test
    fun `the dialog's estimate is the import's own`() = runTest {
        val estimate = ExportEstimate(50_000L, 4_000_000L, listOf("DNS"))
        val exporter = mockk<ReportExporter> { coEvery { exportEstimate(scan) } returns estimate }
        val vm = importedVm(exporter)

        vm.loadExportEstimate()

        assertEquals(estimate, vm.exportEstimate.value)
        assertFalse(vm.estimateFailed.value)
    }

    @Test
    fun `an unreadable estimate is shown as unknown`() = runTest {
        val exporter = mockk<ReportExporter> { coEvery { exportEstimate(scan) } throws IOException("db") }
        val vm = importedVm(exporter)

        vm.loadExportEstimate()

        assertNull(vm.exportEstimate.value)
        assertTrue(vm.estimateFailed.value)
    }

    @Test
    fun `a failed export is reported, not thrown`() = runTest {
        val exporter = mockk<ReportExporter> { coEvery { export(any(), any()) } throws IOException("disk full") }
        val vm = importedVm(exporter)

        vm.exportReport(ExportMode.BOTH)

        assertTrue(vm.exportFailed.value)
        assertFalse(vm.exporting.value)
        assertNull(vm.shareUri.value)
        vm.dismissExportFailed()
        assertFalse(vm.exportFailed.value)
    }

    @Test
    fun `every Export button on the import screen opens the export dialog`() {
        val root = listOf(File("src/main"), File("app/src/main")).first { it.isDirectory }
        val screen = File(root, "java/com/androdr/ui/bugreport/BugReportScreen.kt").readText()
        // No button may start an export directly: that is the silent full-report path.
        assertFalse(screen.contains("viewModel::exportReport"))
        assertFalse(screen.contains("onClick = { viewModel.exportReport("))
        assertTrue(screen.contains("ExportModeDialog("))
        assertEquals(1, Regex("""viewModel\.exportReport\(""").findAll(screen).count())
        // While the report is written, the button shows progress.
        assertTrue(screen.contains("CircularProgressIndicator"))
    }
}
