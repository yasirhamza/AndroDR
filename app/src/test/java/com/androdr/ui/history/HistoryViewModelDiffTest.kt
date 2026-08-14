package com.androdr.ui.history

import com.androdr.data.model.ScanResult
import com.androdr.data.repo.ScanRepository
import com.androdr.scanner.ScanOrchestrator
import com.androdr.sigma.Finding
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test

/**
 * Orientation gate for [HistoryViewModel.selectedDiff].
 *
 * [ScanRepository.allScans] is newest-first (`ScanResultDao`: `ORDER BY
 * timestamp DESC`), so the neighbour at `idx + 1` is OLDER than the selected
 * scan, while [ScanOrchestrator.computeDiff] takes `(newer, older)`. Handing it
 * the pair the other way round type-checks perfectly and silently inverts the
 * History detail section: new risks render under "resolved" and resolved risks
 * under "new risks" (`HistoryScreen.DiffSection`). Worse, since the skip set is
 * read from the FIRST argument's capability-skip entries, the fail-closed
 * protection would be applied to the wrong scan.
 *
 * Nothing else can catch this: both arguments are [ScanResult], both orderings
 * compile, and the diff's own semantics (covered by
 * `ScanOrchestratorDiffTest`) are symmetric-looking. So this test asserts the
 * argument order the ViewModel actually uses.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class HistoryViewModelDiffTest {

    private val mainDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() = Dispatchers.setMain(mainDispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun scan(id: Long, ruleId: String): ScanResult = ScanResult(
        id = id,
        timestamp = id,
        findings = listOf(Finding(ruleId = ruleId, title = ruleId, level = "critical", triggered = true)),
        bugReportFindings = emptyList(),
        riskySideloadCount = 0,
        knownMalwareCount = 0
    )

    @Test
    fun `selectedDiff passes the selected scan as newer and its predecessor as older`() =
        runTest(mainDispatcher) {
            val newer = scan(id = 2L, ruleId = "androdr-new")
            val older = scan(id = 1L, ruleId = "androdr-old")

            val repository = mockk<ScanRepository>()
            // Newest-first, as the DAO query returns it.
            every { repository.allScans } returns flowOf(listOf(newer, older))

            val newerArg = slot<ScanResult>()
            val olderArg = slot<ScanResult>()
            val orchestrator = mockk<ScanOrchestrator>()
            every { orchestrator.computeDiff(capture(newerArg), capture(olderArg)) } returns
                ScanOrchestrator.ScanDiff(newFindings = emptyList(), resolvedFindings = emptyList())

            val viewModel = HistoryViewModel(
                repository = repository,
                orchestrator = orchestrator,
                reportExporter = mockk(relaxed = true),
                dnsEventDao = mockk(relaxed = true),
                appContext = mockk(relaxed = true)
            )

            viewModel.selectScan(newer)
            val diff = viewModel.selectedDiff.filterNotNull().first()

            assertNotNull(diff)
            assertEquals(
                "The selected (newer) scan must be computeDiff's FIRST argument",
                2L, newerArg.captured.id
            )
            assertEquals(
                "The older neighbour must be computeDiff's SECOND argument",
                1L, olderArg.captured.id
            )
        }
}
