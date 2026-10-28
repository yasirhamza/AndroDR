package com.androdr.ui.history

import com.androdr.data.model.ScanResult
import com.androdr.data.repo.FindingsRepository
import com.androdr.data.repo.ScanRepository
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
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
import org.junit.Before
import org.junit.Test

/**
 * Orientation and boundedness gate for [HistoryViewModel.selectedDiff].
 *
 * The selected scan's predecessor ([ScanRepository.previousOf], the next OLDER COMPLETE scan) is
 * the baseline. Swapping the pair type-checks perfectly and silently inverts the History detail
 * section: new risks render under "resolved" and resolved risks under "new risks"
 * (`HistoryScreen.DiffSection`), and the fail-closed skip set would be read from the wrong scan.
 * The diff is computed from rule counts in SQL with a bounded sample (review I1): it never reads
 * either scan whole, so selecting a 100k-finding import cannot exhaust the heap.
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
    fun `selectedDiff treats the selected scan as newer and reads no scan whole`() = runTest(mainDispatcher) {
        val newer = scan(id = 2L)
        val older = scan(id = 1L)

        val repository = mockk<ScanRepository>()
        every { repository.pagedScans() } returns flowOf(androidx.paging.PagingData.from(listOf(newer, older)))
        every { repository.hasScans } returns flowOf(true)
        coEvery { repository.previousOf(newer) } returns older
        val findings = mockk<FindingsRepository>()
        coEvery { findings.triggeredRuleCounts(2L) } returns mapOf("new" to 3, "kept" to 1)
        coEvery { findings.triggeredRuleCounts(1L) } returns mapOf("old" to 2, "kept" to 1)
        coEvery { findings.ruleSample(2L, "new", any()) } returns listOf(finding("new"))
        coEvery { findings.ruleSample(1L, "old", any()) } returns listOf(finding("old"))

        val viewModel = HistoryViewModel(
            repository = repository,
            reportExporter = mockk(relaxed = true),
            findings = findings,
            scanLock = com.androdr.data.repo.ScanLock(),
        )

        viewModel.selectScan(newer)
        val diff = viewModel.selectedDiff.filterNotNull().first()

        assertEquals("the selected (newer) scan's rule is new", listOf("new"), diff.newFindings.map { it.ruleId })
        assertEquals("the older neighbour's rule is resolved", listOf("old"), diff.resolvedFindings.map { it.ruleId })
        assertEquals("exact counts", 3, diff.newCount)
        assertEquals(2, diff.resolvedCount)
        coVerify(exactly = 0) { findings.findingsOf(any(), any()) }
        coVerify(exactly = 0) { findings.withFindings(any(), any()) }
    }
}
