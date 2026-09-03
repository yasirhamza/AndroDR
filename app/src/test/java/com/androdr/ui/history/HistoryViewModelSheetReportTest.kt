package com.androdr.ui.history

import com.androdr.cellular.CellularState
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.ScanRepository
import com.androdr.scanner.ScanOrchestrator
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The detail sheet's report must carry the radio telemetry the process holds.
 *
 * [HistoryViewModel.openSheet] renders a lighter report than the exporter,
 * and it once left every cellular argument at its default: the sheet said
 * "No radio telemetry captured since the app started" while the Cellular
 * card one tab away showed the observation. Found on a device; no test drove
 * the sheet path.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class HistoryViewModelSheetReportTest {

    private val mainDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(mainDispatcher)
        CellularState.reset()
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        CellularState.reset()
    }

    private fun snapshot() = CellularSnapshot(
        mcc = "427", mnc = "02", tac = 171, ci = 3046670L, pci = 45,
        earfcn = 425, bands = listOf(1), bandwidthKhz = null, rat = "LTE",
        operatorAlphaLong = "Vodafone Qatar", operatorAlphaShort = "Vodafone Qatar",
        additionalPlmns = emptyList(), neighborCount = 9, servingRsrp = -69,
        isRegistered = true, capturedAt = 1_000L, source = TelemetrySource.LIVE_SCAN,
        previousTac = null, previousRat = null, tacChanged = false, ratChanged = false,
        tacChangesLast5m = 0, servingMinusMaxNeighborRsrpDb = null,
        locationMovedMLast5m = null,
    )

    private fun viewModel(): HistoryViewModel {
        val repository = mockk<ScanRepository>()
        every { repository.allScans } returns flowOf(emptyList())
        val orchestrator = mockk<ScanOrchestrator>()
        every { orchestrator.lastAppTelemetry } returns emptyList()
        return HistoryViewModel(
            repository = repository,
            orchestrator = orchestrator,
            reportExporter = mockk(relaxed = true),
            dnsEventDao = mockk(relaxed = true),
            appContext = mockk(relaxed = true),
        )
    }

    @Test
    fun `the sheet report shows the radio telemetry the process holds`() = runTest(mainDispatcher) {
        CellularState.record(snapshot(), emptyList())
        val scan = ScanResult(
            id = 1L, timestamp = 1_000L, findings = emptyList(), bugReportFindings = emptyList(),
            riskySideloadCount = 0, knownMalwareCount = 0,
        )

        val vm = viewModel()
        vm.openSheet(scan)
        val text = vm.sheetReportText.filter { it.isNotEmpty() }.first()

        assertTrue(
            "the sheet must render the observation the process holds",
            text.contains("Radio updates delivered since the app started: 1"),
        )
        assertFalse(
            "the sheet must not claim the monitor never ran",
            text.contains("No radio telemetry captured"),
        )
        // Same redaction as every other handoff path.
        listOf("171", "3046670", "Vodafone Qatar", "427/02").forEach {
            assertFalse("tower identity reached the sheet report: $it", text.contains(it))
        }
    }
}
