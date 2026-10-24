package com.androdr.ui.history

import com.androdr.data.model.ScanResult
import com.androdr.data.repo.ScanRepository
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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A7c: [ScanRepository.deleteScan] / [ScanRepository.deleteAllScans] return false when a scan or
 * import holds the writer lock. The ViewModel used to ignore that, so the user tapped Delete and
 * nothing happened. It must now say so, and a refused clear-all must not drop the selection.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class HistoryViewModelDeleteRefusedTest {

    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private val scan = ScanResult(
        id = 1L, timestamp = 1L, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0,
    )

    private fun vm(repository: ScanRepository) = HistoryViewModel(
        repository = repository,
        reportExporter = mockk(relaxed = true),
        findings = mockk(relaxed = true),
    )

    private fun repo(deleteOne: Boolean, deleteAll: Boolean) = mockk<ScanRepository> {
        every { pagedScans() } returns flowOf(androidx.paging.PagingData.from(listOf(scan)))
        every { hasScans } returns flowOf(true)
        coEvery { deleteScan(any()) } returns deleteOne
        coEvery { deleteAllScans() } returns deleteAll
    }

    @Test
    fun `a refused single delete is surfaced`() = runTest {
        val vm = vm(repo(deleteOne = false, deleteAll = true))
        vm.requestDeleteScan(1L)
        vm.confirmDeleteScan()
        assertTrue(vm.deleteRefused.value)
        vm.dismissDeleteRefused()
        assertFalse(vm.deleteRefused.value)
    }

    @Test
    fun `a delete that ran is not reported as refused`() = runTest {
        val vm = vm(repo(deleteOne = true, deleteAll = true))
        vm.requestDeleteScan(1L)
        vm.confirmDeleteScan()
        assertFalse(vm.deleteRefused.value)
    }

    @Test
    fun `a refused clear-all is surfaced and keeps the selection`() = runTest {
        val vm = vm(repo(deleteOne = true, deleteAll = false))
        vm.selectScan(scan)
        vm.requestClearAll()
        vm.confirmClearAll()
        assertTrue(vm.deleteRefused.value)
        assertEquals(scan, vm.selectedScan.value)
    }

    @Test
    fun `a clear-all that ran clears the selection`() = runTest {
        val vm = vm(repo(deleteOne = true, deleteAll = true))
        vm.selectScan(scan)
        vm.requestClearAll()
        vm.confirmClearAll()
        assertFalse(vm.deleteRefused.value)
        assertEquals(null, vm.selectedScan.value)
    }

    @Test
    fun `source gate - the screen renders the refusal`() {
        val src = java.io.File("src/main/java/com/androdr/ui/history/HistoryScreen.kt").readText()
        assertTrue(src.contains("viewModel.deleteRefused"))
        assertTrue(src.contains("history_delete_refused_body"))
    }
}
