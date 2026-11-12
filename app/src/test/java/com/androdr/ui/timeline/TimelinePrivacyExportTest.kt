package com.androdr.ui.timeline

import androidx.lifecycle.SavedStateHandle
import com.androdr.R
import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.TelemetrySource
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.toList
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/** Exports leave privacy entries out; with nothing else to export they say so (spec 2026-11-10 §5.3). */
@OptIn(ExperimentalCoroutinesApi::class)
class TimelinePrivacyExportTest {
    private val dispatcher = StandardTestDispatcher()

    @Before fun setUp() = Dispatchers.setMain(dispatcher)

    @After fun tearDown() = Dispatchers.resetMain()

    private val entries: TimelineEntries = mockk(relaxed = true) {
        coEvery { count(match { it.exportable }) } returns 0L
        coEvery { count(match { !it.exportable }) } returns 4L
    }

    private fun vm() = TimelineViewModel(
        appContext = mockk(relaxed = true),
        db = mockk(relaxed = true),
        entries = entries,
        knownAppResolver = mockk(relaxed = true),
        sigmaRuleEngine = mockk(relaxed = true),
        scanRepository = mockk(relaxed = true),
        reportExporter = mockk(relaxed = true),
        clusterMembers = mockk(relaxed = true),
        signalMembers = mockk(relaxed = true),
        findingsRepository = mockk(relaxed = true),
        savedState = SavedStateHandle(),
    ).also { it.io = dispatcher }

    @Test fun `export with only privacy entries says there is nothing to export`() = runTest(dispatcher) {
        val model = vm()
        model.exportCsv()
        advanceUntilIdle()
        assertEquals(R.string.timeline_nothing_to_export, model.notice.value)
        assertNull(model.shareUri.value)
        coVerify(exactly = 0) { entries.forEachPage(any(), any(), any(), any()) }
        model.noticeShown()
        assertNull(model.notice.value)
    }

    @Test fun `the report says the same and writes nothing`() = runTest(dispatcher) {
        val model = vm()
        model.generateReport()
        advanceUntilIdle()
        assertEquals(R.string.timeline_nothing_to_export, model.notice.value)
        coVerify(exactly = 0) { entries.forEachPage(any(), any(), any(), any()) }
        coVerify { entries.count(match<TimelineFilter> { it.exportable }) }
        assertEquals("the report sheet says so instead of waiting", ReportPreview.NOTHING, model.report.value)
    }

    @Test fun `a new report starts from an empty preview, never the last one`() = runTest(dispatcher) {
        val model = vm()
        model.generateReport()
        advanceUntilIdle()
        assertEquals(ReportPreview.NOTHING, model.report.value)
        model.generateReport()
        assertEquals("a pending Copy must wait for this report", ReportPreview.EMPTY, model.report.value)
    }

    @Test fun `a pending copy is cancelled, not kept for the next report`() {
        assertEquals(CopyStep.WAIT, copyStep(pending = true, report = ReportPreview.EMPTY))
        assertEquals(CopyStep.CANCEL, copyStep(pending = true, report = ReportPreview.NOTHING))
        assertEquals(CopyStep.COPY, copyStep(pending = true, report = ReportPreview("text", false)))
        assertEquals(CopyStep.WAIT, copyStep(pending = false, report = ReportPreview("text", false)))
    }

    @Test fun `the privacy header narrows to the privacy scan by source`() = runTest(dispatcher) {
        val model = vm()
        model.setScanFilter(7L)
        model.setGroupMode(TimelineGroupMode.SCAN)
        model.showPrivacyScan()
        assertEquals(TelemetrySource.PRIVACY_SCAN, model.filter.value.source)
        assertNull(model.filter.value.scanId)
        assertEquals(TimelineGroupMode.DATE, model.groupMode.value)
    }

    @Test fun `a security scan header leaves the privacy filter behind`() = runTest(dispatcher) {
        val model = vm()
        model.showPrivacyScan()
        model.showScan(7L)
        assertEquals(7L, model.filter.value.scanId)
        assertNull(model.filter.value.source)
        assertEquals(TimelineGroupMode.DATE, model.groupMode.value)
        model.setSourceFilter(TelemetrySource.BUGREPORT_IMPORT)
        model.showScan(8L)
        assertEquals("another source filter is kept", TelemetrySource.BUGREPORT_IMPORT, model.filter.value.source)
    }

    @Test fun `the privacy header counts the privacy scan's entries`() = runTest(dispatcher) {
        coEvery { entries.count(match { it.source == TelemetrySource.PRIVACY_SCAN && it.scanId == null }) } returns 9L
        val model = vm()
        model.setScanFilter(7L)
        assertEquals(9L, model.privacyCount())
    }

    @Test fun `the privacy scan time is passed on only when it changes`() = runTest(dispatcher) {
        assertEquals(listOf(null, 5L, 7L), privacyTimes(flowOf(null, 5L, 5L, 5L, 7L, 7L)).toList())
    }
}
