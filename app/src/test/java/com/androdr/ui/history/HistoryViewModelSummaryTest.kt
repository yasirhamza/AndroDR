package com.androdr.ui.history

import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.data.repo.ScanRepository
import com.androdr.reporting.ExportEstimate
import com.androdr.reporting.ReportExporter
import com.androdr.reporting.ReportSummary
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flowOf
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

/**
 * The History sheet shows [ReportExporter.summary] (the full report is exported, never built for
 * the sheet), the export dialog shows [ReportExporter.exportEstimate], and a failed read or export
 * is surfaced instead of crashing the screen.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class HistoryViewModelSummaryTest {

    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private val scan = ScanResult(
        id = 1L, timestamp = 1L, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0,
    )
    private val summary = ReportSummary(TelemetrySource.LIVE_SCAN, "LOW", 0, 0, 0, 0, 0, TelemetryState.STORED,
        emptyList())

    private fun vm(exporter: ReportExporter) = HistoryViewModel(
        repository = mockk<ScanRepository> {
            every { pagedScans() } returns flowOf(androidx.paging.PagingData.from(listOf(scan)))
            every { hasScans } returns flowOf(true)
        },
        reportExporter = exporter,
        findings = mockk(relaxed = true),
        scanLock = com.androdr.data.repo.ScanLock(),
    )

    @Test
    fun `the sheet shows the exporter's summary of the opened scan`() = runTest {
        val vm = vm(mockk { coEvery { summary(scan) } returns summary })
        vm.openSheet(scan)
        assertEquals(summary, vm.sheetSummary.value)
        assertFalse(vm.sheetFailed.value)
    }

    @Test
    fun `a summary that cannot be read is surfaced, not thrown`() = runTest {
        val vm = vm(mockk { coEvery { summary(scan) } throws IllegalStateException("db closed") })
        vm.openSheet(scan)
        assertNull(vm.sheetSummary.value)
        assertTrue(vm.sheetFailed.value)
    }

    @Test
    fun `the export dialog gets the exporter's estimate`() = runTest {
        val estimate = ExportEstimate(3, 1_000, listOf("installed apps"))
        val vm = vm(mockk { coEvery { exportEstimate(scan) } returns estimate })
        vm.loadExportEstimate(scan)
        assertEquals(estimate, vm.exportEstimate.value)
    }

    @Test
    fun `a failed export is surfaced and the export can be retried`() = runTest {
        val vm = vm(mockk { coEvery { export(scan, any()) } throws java.io.IOException("disk full") })
        vm.exportReport(scan)
        assertTrue(vm.exportFailed.value)
        assertFalse(vm.exporting.value)
        assertNull(vm.shareUri.value)
    }

    @Test
    fun `a failed estimate says the size is unknown instead of loading forever`() = runTest {
        val vm = vm(mockk { coEvery { exportEstimate(scan) } throws IllegalStateException("db closed") })
        vm.loadExportEstimate(scan)
        assertNull(vm.exportEstimate.value)
        assertTrue(vm.estimateFailed.value)
    }

    @Test
    fun `a slow estimate for an earlier dialog never lands in the current one`() = runTest {
        val other = scan.copy(id = 2L)
        val slow = kotlinx.coroutines.CompletableDeferred<ExportEstimate>()
        val forOther = ExportEstimate(9, 9_000, listOf("DNS lookups"))
        val vm = vm(mockk {
            coEvery { exportEstimate(scan) } coAnswers { slow.await() }
            coEvery { exportEstimate(other) } returns forOther
        })
        vm.loadExportEstimate(scan)
        vm.loadExportEstimate(other)
        slow.complete(ExportEstimate(1, 100, listOf("installed apps")))
        assertEquals(forOther, vm.exportEstimate.value)
    }
}
