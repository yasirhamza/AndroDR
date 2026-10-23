package com.androdr.ui.dashboard

import com.androdr.data.model.ScanWithFindings
import com.androdr.data.model.scanWith
import com.androdr.data.model.TelemetryState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** A7c: the Dashboard's storage warnings and the "unsaved result" handling. */
class StorageFailedBannerTest {

    private fun scan(id: Long = 1L, state: TelemetryState = TelemetryState.STORED) = scanWith(
        id = id, timestamp = id, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, telemetryState = state,
    )

    private fun banner(
        scan: ScanWithFindings?, scanning: Boolean = false, unsaved: Boolean = false, flag: Boolean = false,
    ) = DashboardViewModel.storageBanner(scan, scanning, unsaved, flag)

    @Test
    fun `a saved FAILED scan says some records were not saved`() =
        assertEquals(StorageBanner.PARTLY_STORED, banner(scan(state = TelemetryState.FAILED)))

    @Test
    fun `stored, partial-retention and none show nothing`() {
        for (s in listOf(TelemetryState.STORED, TelemetryState.PARTIAL_RETENTION, TelemetryState.NONE)) {
            assertEquals("$s", StorageBanner.NONE, banner(scan(state = s)))
        }
        assertEquals(StorageBanner.NONE, banner(null))
    }

    @Test
    fun `a scan that was not saved at all says so, even over a clean scan`() {
        assertEquals(StorageBanner.NOT_SAVED, banner(scan(), unsaved = true))
    }

    @Test
    fun `after a restart the flag alone never says the scan on screen was not saved`() {
        // The in-memory result is gone; the screen shows an older saved scan.
        assertEquals(StorageBanner.EARLIER_SCAN_SHOWN, banner(scan(), unsaved = false, flag = true))
    }

    @Test
    fun `a failed import with a saved live scan on screen does not mark that scan unsaved`() {
        val live = scan(id = 5L)
        val outcome = DashboardViewModel.outcomeOf(live, saved = true)!!
        assertNull("the live scan was saved", outcome.unsaved)
        // The import's failure set the flag; the live scan is still the one displayed.
        assertEquals(StorageBanner.EARLIER_SCAN_SHOWN, banner(live, unsaved = outcome.unsaved != null, flag = true))
    }

    @Test
    fun `the not-saved banner needs the displayed scan itself to be unsaved`() {
        assertEquals(StorageBanner.NOT_SAVED, banner(scan(), unsaved = true, flag = false))
        assertEquals(StorageBanner.NOT_SAVED, banner(scan(), unsaved = true, flag = true))
    }

    @Test
    fun `earlier-scan copy does not vouch for the screen and not-saved copy is true of the screen`() {
        val strings = java.io.File("src/main/res/values/strings.xml").readText()
        val earlier = Regex("name=\"storage_earlier_banner_body\">([^<]*)").find(strings)!!.groupValues[1]
        assertTrue(!earlier.contains("findings are shown"))
        assertTrue(earlier.contains("earlier"))
        val notSaved = Regex("name=\"storage_not_saved_banner_body\">([^<]*)").find(strings)!!.groupValues[1]
        assertTrue("no storage cause is asserted for any unsaved scan", !notSaved.contains("ran out"))
    }

    @Test
    fun `a failed history read concludes nothing, cancellation propagates`() = kotlinx.coroutines.runBlocking {
        assertNull(DashboardViewModel.readPersisted { error("database closed") })
        assertNull(DashboardViewModel.outcomeOf(scan(), null))
        val ok = DashboardViewModel.readPersisted { listOf(9L) }
        assertEquals(1, ok!!.size)
        var cancelled = false
        try {
            DashboardViewModel.readPersisted { throw kotlinx.coroutines.CancellationException("x") }
        } catch (_: kotlinx.coroutines.CancellationException) {
            cancelled = true
        }
        assertTrue(cancelled)
    }

    @Test
    fun `nothing shows while a scan runs`() {
        assertEquals(StorageBanner.NONE, banner(scan(state = TelemetryState.FAILED), scanning = true, unsaved = true))
    }

    @Test
    fun `an unsaved in-memory result replaces the older clean scan as the latest`() {
        val clean = scan(id = 1L)
        val unsaved = scan(id = 2L, state = TelemetryState.FAILED)
        assertSame(unsaved, DashboardViewModel.resolveLatest(clean, unsaved))
        assertSame(clean, DashboardViewModel.resolveLatest(clean, null))
    }

    @Test
    fun `a result is unsaved exactly when no saved scan has its id`() {
        val r = scan(id = 2L)
        assertNull(DashboardViewModel.unsavedOrNull(r, saved = true))
        assertSame(r, DashboardViewModel.unsavedOrNull(r, saved = false))
    }

    @Test
    fun `the health flag clears only after a scan that was saved with all its records`() {
        assertTrue(DashboardViewModel.shouldClearHealthFlag(scan(id = 2L), saved = true))
        assertTrue(!DashboardViewModel.shouldClearHealthFlag(scan(id = 3L), saved = false))
        val failed = scan(id = 2L, state = TelemetryState.FAILED)
        assertTrue(!DashboardViewModel.shouldClearHealthFlag(failed, saved = true))
    }

    @Test
    fun `source gate - the scan result is kept and the screen renders the helper`() {
        val vm = java.io.File("src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt").readText()
        assertTrue("runFullScan's result must not be discarded", vm.contains("val result = orchestrator.runFullScan()"))
        val screen = java.io.File("src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt").readText()
        assertTrue(screen.contains("DashboardViewModel.storageBanner("))
        assertTrue(screen.contains("storage_not_saved_banner_body"))
        assertTrue(screen.contains("dns_drops_banner_body"))
    }
}
