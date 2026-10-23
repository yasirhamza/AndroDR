package com.androdr.ui.history

import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanWithFindings
import com.androdr.data.repo.FindingsRepository
import com.androdr.data.repo.ScanRepository
import com.androdr.scanner.ScanOrchestrator
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import io.mockk.coEvery
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
 * The selected scan's predecessor ([ScanRepository.previousOf], the next OLDER COMPLETE scan) is
 * the baseline, while [ScanOrchestrator.computeDiff] takes `(newer, older)`. Handing it the pair
 * the other way round type-checks perfectly and silently inverts the History detail section: new
 * risks render under "resolved" and resolved risks under "new risks" (`HistoryScreen.DiffSection`).
 * Worse, since the skip set is read from the FIRST argument's capability-skip entries, the
 * fail-closed protection would be applied to the wrong scan.
 *
 * Nothing else can catch this: both arguments are [ScanWithFindings], both orderings compile, and
 * the diff's own semantics (covered by `ScanOrchestratorDiffTest`) are symmetric-looking. So this
 * test asserts the argument order the ViewModel actually uses.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class HistoryViewModelDiffTest {

    private val mainDispatcher = UnconfinedTestDispatcher()

    @Before
    fun setUp() = Dispatchers.setMain(mainDispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun scan(id: Long): ScanResult = ScanResult(
        id = id, timestamp = id, bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0,
    )

    private fun finding(ruleId: String) =
        Finding(ruleId = ruleId, title = ruleId, level = "critical", category = FindingCategory.APP_RISK)

    @Test
    fun `selectedDiff passes the selected scan as newer and its predecessor as older`() =
        runTest(mainDispatcher) {
            val newer = scan(id = 2L)
            val older = scan(id = 1L)

            val repository = mockk<ScanRepository>()
            every { repository.pagedScans() } returns flowOf(androidx.paging.PagingData.from(listOf(newer, older)))
            every { repository.hasScans } returns flowOf(true)
            coEvery { repository.previousOf(newer) } returns older
            val findings = mockk<FindingsRepository>()
            coEvery { findings.withFindings(newer, true) } returns ScanWithFindings(newer, listOf(finding("new")))
            coEvery { findings.withFindings(older, true) } returns ScanWithFindings(older, listOf(finding("old")))

            val newerArg = slot<ScanWithFindings>()
            val olderArg = slot<ScanWithFindings>()
            val orchestrator = mockk<ScanOrchestrator>()
            every { orchestrator.computeDiff(capture(newerArg), capture(olderArg)) } returns
                ScanOrchestrator.ScanDiff(newFindings = emptyList(), resolvedFindings = emptyList())

            val viewModel = HistoryViewModel(
                repository = repository,
                orchestrator = orchestrator,
                reportExporter = mockk(relaxed = true),
                findings = findings,
            )

            viewModel.selectScan(newer)
            val diff = viewModel.selectedDiff.filterNotNull().first()

            assertNotNull(diff)
            assertEquals("The selected (newer) scan must be computeDiff's FIRST argument", 2L, newerArg.captured.id)
            assertEquals("The older neighbour must be computeDiff's SECOND argument", 1L, olderArg.captured.id)
            assertEquals("new", newerArg.captured.findings.single().ruleId)
        }
}
