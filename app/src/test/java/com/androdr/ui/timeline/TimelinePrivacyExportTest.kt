package com.androdr.ui.timeline

import androidx.lifecycle.SavedStateHandle
import com.androdr.R
import com.androdr.data.db.TimelineFilter
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
    }
}
