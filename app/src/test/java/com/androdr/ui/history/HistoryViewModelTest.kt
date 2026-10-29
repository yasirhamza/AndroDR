package com.androdr.ui.history

import com.androdr.data.db.StoredFindingCounts
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.DeleteResult
import com.androdr.data.repo.FindingsRepository
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.ScanRepository
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
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
 * D3 (spec §5.4) and A7c: deletes return [DeleteResult]. [DeleteResult.ScanRunning] (a scan or
 * import holds the writer lock) changes nothing and the screen says so ("A scan is running — try
 * again when it finishes"); a refused "Clear all" keeps the selection. Delete is disabled from
 * [ScanLock.writerRunning]. A History row counts stored findings as the import screen does and says
 * how many could not be saved, so the count stays honest after the import card is dismissed.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class HistoryViewModelTest {

    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private val scan = ScanResult(
        id = 1L, timestamp = 1L, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, triggeredCount = 7,
    )

    private fun vm(
        repository: ScanRepository,
        lock: ScanLock = ScanLock(),
        findings: FindingsRepository = mockk(relaxed = true),
    ) = HistoryViewModel(repository = repository, reportExporter = mockk(relaxed = true), findings = findings,
        scanLock = lock)

    private fun repo(deleteOne: DeleteResult, deleteAll: DeleteResult) = mockk<ScanRepository> {
        every { pagedScans() } returns flowOf(androidx.paging.PagingData.from(listOf(scan)))
        every { hasScans } returns flowOf(true)
        coEvery { deleteScan(any()) } returns deleteOne
        coEvery { deleteAllScans() } returns deleteAll
    }

    @Test
    fun `delete is disabled while writerRunning is true`() = runTest {
        val lock = ScanLock()
        val vm = vm(repo(DeleteResult.Done, DeleteResult.Done), lock)
        assertTrue(vm.deleteEnabled.value)
        val inside = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val writer = launch(Dispatchers.Default) {
            lock.withWriter {
                inside.complete(Unit)
                release.await()
            }
        }
        inside.await()
        assertTrue(lock.writerRunning.value)
        assertFalse("delete disabled while a scan or import runs", vm.deleteEnabled.value)
        release.complete(Unit)
        writer.join()
        assertTrue(vm.deleteEnabled.value)
    }

    @Test
    fun `ScanRunning on a single delete shows the message`() = runTest {
        val vm = vm(repo(deleteOne = DeleteResult.ScanRunning, deleteAll = DeleteResult.Done))
        vm.requestDeleteScan(1L)
        vm.confirmDeleteScan()
        assertTrue(vm.deleteRefused.value)
        vm.dismissDeleteRefused()
        assertFalse(vm.deleteRefused.value)
    }

    @Test
    fun `a delete that ran is not reported as refused and drops a selection of that scan`() = runTest {
        val vm = vm(repo(deleteOne = DeleteResult.Done, deleteAll = DeleteResult.Done))
        vm.selectScan(scan)
        vm.requestDeleteScan(1L)
        vm.confirmDeleteScan()
        assertFalse(vm.deleteRefused.value)
        assertEquals(null, vm.selectedScan.value)
    }

    @Test
    fun `ScanRunning on clear-all shows the message and keeps the selection`() = runTest {
        val vm = vm(repo(deleteOne = DeleteResult.Done, deleteAll = DeleteResult.ScanRunning))
        vm.selectScan(scan)
        vm.requestClearAll()
        vm.confirmClearAll()
        assertTrue(vm.deleteRefused.value)
        assertEquals(scan, vm.selectedScan.value)
    }

    @Test
    fun `a clear-all that ran clears the selection`() = runTest {
        val vm = vm(repo(deleteOne = DeleteResult.Done, deleteAll = DeleteResult.Done))
        vm.selectScan(scan)
        vm.requestClearAll()
        vm.confirmClearAll()
        assertFalse(vm.deleteRefused.value)
        assertEquals(null, vm.selectedScan.value)
    }

    /** Review I1: a delete that throws (a full disk) is reported, never a crash, and changes no selection. */
    @Test
    fun `a delete or clear-all that throws shows the failure instead of crashing`() = runTest {
        val repository = mockk<ScanRepository> {
            every { pagedScans() } returns flowOf(androidx.paging.PagingData.from(listOf(scan)))
            every { hasScans } returns flowOf(true)
            coEvery { deleteScan(any()) } throws android.database.sqlite.SQLiteFullException("database or disk is full")
            coEvery { deleteAllScans() } throws java.io.IOException("No space left on device")
        }
        val vm = vm(repository)
        vm.selectScan(scan)
        vm.requestDeleteScan(1L)
        vm.confirmDeleteScan()
        assertTrue(vm.deleteFailed.value)
        assertFalse(vm.deleteRefused.value)
        assertEquals(scan, vm.selectedScan.value)
        vm.dismissDeleteFailed()
        assertFalse(vm.deleteFailed.value)
        vm.requestClearAll()
        vm.confirmClearAll()
        assertTrue(vm.deleteFailed.value)
        assertEquals(scan, vm.selectedScan.value)
        val src = java.io.File("src/main/java/com/androdr/ui/history/HistoryScreen.kt").readText()
        assertTrue("the screen renders the failure", src.contains("viewModel.deleteFailed") &&
            src.contains("R.string.history_delete_failed_body"))
    }

    @Test
    fun `a row counts shown stored findings and says how many could not be saved`() = runTest {
        val findings = mockk<FindingsRepository> { coEvery { rowCounts(1L) } returns StoredFindingCounts(3, 4) }
        val vm = vm(repo(DeleteResult.Done, DeleteResult.Done), findings = findings)
        assertEquals(HistoryRowCounts(shown = 3, unsaved = 3), vm.rowCounts(scan))
        coVerify(exactly = 1) { findings.rowCounts(1L) }
        val saved = mockk<FindingsRepository> { coEvery { rowCounts(1L) } returns StoredFindingCounts(7, 7) }
        assertEquals(HistoryRowCounts(7, 0), vm(repo(DeleteResult.Done, DeleteResult.Done), findings = saved)
            .rowCounts(scan))
    }

    @Test
    fun `source gate - the screen renders the refusal, the writer gate and the honest copy`() {
        val src = java.io.File("src/main/java/com/androdr/ui/history/HistoryScreen.kt").readText()
        assertTrue(src.contains("viewModel.deleteRefused"))
        assertTrue(src.contains("history_delete_refused_body"))
        assertTrue("delete follows writerRunning", src.contains("viewModel.deleteEnabled"))
        assertTrue(src.contains("R.string.history_delete_body"))
        assertTrue(src.contains("R.string.history_clear_body"))
        val strings = java.io.File("src/main/res/values/strings.xml").readText()
        fun string(name: String) = Regex("<string name=\"$name\">([^<]*)</string>").find(strings)!!.groupValues[1]
        assertEquals("A scan is running — try again when it finishes", string("history_delete_refused_body"))
        // R37: alerts and their evidence are never deleted; both dialogs say so.
        assertTrue(string("history_delete_body").contains("Alerts and their evidence are kept"))
        assertTrue(string("history_clear_body").contains("Alerts and their evidence are kept"))
        // Final review M3: Clear all never deletes the DnsEvent table (AlertCloseTest pins that), so the
        // copy must say the DNS log survives rather than that every live DNS event is deleted.
        val clear = string("history_clear_body")
        assertTrue(clear, clear.contains("live DNS events on the Timeline"))
        assertTrue(clear, clear.contains("so is the DNS log shown on the DNS screen and counted on the Dashboard"))
    }
}
