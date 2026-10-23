package com.androdr.ui.bugreport

import android.net.Uri
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetryState
import com.androdr.data.store.Preflight
import com.androdr.reporting.ReportExporter
import com.androdr.scanner.BugReportAnalyzer
import com.androdr.scanner.ImportPreflight
import com.androdr.scanner.IntrusionLogAnalysisResult
import com.androdr.scanner.IntrusionLogStats
import com.androdr.scanner.ScanOrchestrator
import com.androdr.scanner.WriteResult
import com.androdr.timelineForScan
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
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * C3: an import's records live in the store, so the import screen links to the Timeline filtered
 * to the import's scan, and Export writes that scan's report through the one report path.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BugReportTimelineLinkTest {

    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private val uri = mockk<Uri>(relaxed = true)
    private val scan = ScanResult(id = 42L, timestamp = 42L, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0)
    private val write = WriteResult(1, 0, 0, TelemetryState.STORED, scan)
    private val exporter = mockk<ReportExporter>(relaxed = true)

    private fun vm(analysis: ScanOrchestrator.ArtifactAnalysis) = BugReportViewModel(
        mockk { coEvery { analyzeArtifact(any()) } returns analysis },
        mockk<ImportPreflight> { coEvery { check(any()) } returns Preflight.Ok },
        exporter,
        mockk(relaxed = true),
    )

    private val bugReport = ScanOrchestrator.ArtifactAnalysis.BugReport(
        BugReportAnalyzer.BugReportAnalysisResult(write = write))

    @Test
    fun `a bug report import links to its scan, and export writes that scan's report`() = runTest {
        val vm = vm(bugReport)
        assertNull(vm.importScanId.value)

        vm.onFilePicked(uri)
        vm.exportReport()

        assertEquals(42L, vm.importScanId.value)
        coVerify(exactly = 1) { exporter.export(scan, any()) }
    }

    @Test
    fun `an intrusion-log import links to its scan`() = runTest {
        val stats = IntrusionLogStats(0, 0, 0, 0, 0, null, null)
        val vm = vm(ScanOrchestrator.ArtifactAnalysis.IntrusionLog(
            IntrusionLogAnalysisResult(stats, write = write)))
        vm.onFilePicked(uri)
        assertEquals(42L, vm.importScanId.value)
    }

    @Test
    fun `before any import there is no link and export does nothing`() = runTest {
        val vm = vm(bugReport)
        vm.exportReport()
        assertNull(vm.importScanId.value)
        coVerify(exactly = 0) { exporter.export(any(), any()) }
    }

    @Test
    fun `the link opens the Timeline route filtered by scan`() {
        assertEquals("timeline?scan=42", timelineForScan(42L))
    }
}
