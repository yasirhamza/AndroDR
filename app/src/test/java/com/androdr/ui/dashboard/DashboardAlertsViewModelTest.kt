package com.androdr.ui.dashboard

import androidx.paging.PagingData
import com.androdr.data.repo.AlertGroupRef
import com.androdr.data.repo.FindingsRepository
import com.androdr.ui.security.ConfirmResult
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.coVerifyOrder
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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * D3 (spec §5.4): the Dashboard's open-alerts card. Close (one group) and Close selected (bulk, one
 * confirmation) ask the device credential first and pass its result to
 * [FindingsRepository.closeGroups], which closes nothing unless it is confirmed; the selection is
 * cleared only by a close that ran. The screen hosts the card, and every close control is a
 * `ProtectedButton` that goes through `ConfirmCredential`.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DashboardAlertsViewModelTest {

    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private val a = AlertGroupRef("r1", "evil.example", 10L)
    private val b = AlertGroupRef("r2", "", 20L)

    private fun repo(closed: Int) = mockk<FindingsRepository> {
        every { openAlertGroups() } returns flowOf(PagingData.empty())
        coEvery { closeGroups(any(), any(), any()) } answers {
            if (thirdArg<ConfirmResult>() == ConfirmResult.Cancelled) 0 else closed
        }
    }

    @Test
    fun `bulk close asks the credential once, then closes the selection with its result`() = runTest {
        val findings = repo(closed = 5)
        val vm = DashboardAlertsViewModel(findings)
        vm.toggle(a)
        vm.toggle(b)
        vm.requestCloseSelected()
        assertEquals(listOf(a, b).toSet(), vm.pendingClose.value?.toSet())
        var asked = 0
        vm.close("  looked at it ") { asked++; ConfirmResult.Confirmed }
        assertEquals("one confirmation for the whole selection", 1, asked)
        coVerify(exactly = 1) {
            findings.closeGroups(match { it.toSet() == setOf(a, b) }, "looked at it", ConfirmResult.Confirmed)
        }
        assertEquals(CloseOutcome.Closed(5), vm.outcome.value)
        assertTrue("a close that ran clears its groups", vm.selected.value.isEmpty())
        assertNull(vm.pendingClose.value)
    }

    @Test
    fun `a cancelled credential closes nothing and keeps the selection`() = runTest {
        val findings = repo(closed = 3)
        val vm = DashboardAlertsViewModel(findings)
        vm.toggle(a)
        vm.requestCloseSelected()
        vm.close(null) { ConfirmResult.Cancelled }
        coVerify { findings.closeGroups(listOf(a), null, ConfirmResult.Cancelled) }
        assertEquals(CloseOutcome.NothingClosed, vm.outcome.value)
        assertEquals(setOf(a), vm.selected.value)
    }

    @Test
    fun `the credential is asked before anything is closed, and only for a pending close`() = runTest {
        val findings = repo(closed = 1)
        val vm = DashboardAlertsViewModel(findings)
        var asked = false
        vm.close(null) { asked = true; ConfirmResult.Confirmed }
        assertTrue("nothing pending: no prompt", !asked)
        coVerify(exactly = 0) { findings.closeGroups(any(), any(), any()) }
        val confirm = mockk<suspend () -> ConfirmResult>()
        coEvery { confirm() } returns ConfirmResult.Confirmed
        vm.requestClose(a)
        vm.close(null, confirm)
        coVerifyOrder {
            confirm()
            findings.closeGroups(listOf(a), null, ConfirmResult.Confirmed)
        }
    }

    @Test
    fun `a close without a secure lock screen is reported as such`() = runTest {
        val vm = DashboardAlertsViewModel(repo(closed = 2))
        vm.requestClose(a)
        vm.close(null) { ConfirmResult.NoSecureLock }
        assertEquals(CloseOutcome.ClosedWithoutLock(2), vm.outcome.value)
        vm.outcomeShown()
        assertNull(vm.outcome.value)
    }

    @Test
    fun `selection is by rule and matched value`() = runTest {
        val vm = DashboardAlertsViewModel(repo(closed = 0))
        vm.toggle(a)
        vm.toggle(a.copy(maxId = 99L)) // the same group re-paged with a newer alert
        assertTrue(vm.selected.value.isEmpty())
        vm.toggle(a)
        vm.toggle(a.copy(matchedValue = "other.example"))
        assertEquals(2, vm.selected.value.size)
    }

    @Test
    fun `source gate - the Dashboard hosts the card and every close goes through ProtectedButton and the credential`() {
        fun src(path: String) = File("src/main/java/com/androdr/$path").readText()
        val screen = src("ui/dashboard/DashboardScreen.kt")
        assertTrue(screen.contains("OpenAlertsCard("))
        assertTrue("import-only empty state", screen.contains("R.string.dashboard_no_live_scan_alerts"))
        val card = src("ui/dashboard/OpenAlertsCard.kt")
        assertTrue(card.contains(
            "ProtectedButton(onClick = { viewModel.close(note) { confirm(title, description) } })"))
        assertTrue(card.contains(
            "ProtectedButton(\n                    onClick = { viewModel.requestCloseSelected() }"))
        assertTrue(card.contains("rememberConfirmCredential()"))
        val timeline = src("ui/timeline/TimelineEventCard.kt")
        assertTrue(timeline.contains("ProtectedButton(onClick = close"))
        val timelineScreen = src("ui/timeline/TimelineScreen.kt")
        assertTrue(timelineScreen.contains(
            "viewModel.closeAlerts(ids, null) { confirm(closeTitle, closeDescription) }"))
    }
}
