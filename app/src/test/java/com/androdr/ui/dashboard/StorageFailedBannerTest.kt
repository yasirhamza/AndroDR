package com.androdr.ui.dashboard

import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetryState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** A7c: the Dashboard's storage warnings and the "unsaved result" handling. */
class StorageFailedBannerTest {

    private fun scan(id: Long = 1L, state: TelemetryState = TelemetryState.STORED) = ScanResult(
        id = id, timestamp = id, findings = emptyList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, telemetryState = state,
    )

    private fun banner(
        scan: ScanResult?, scanning: Boolean = false, unsaved: Boolean = false, flag: Boolean = false,
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
    fun `the persistent health flag shows the not-saved warning`() {
        assertEquals(StorageBanner.NOT_SAVED, banner(scan(), flag = true))
    }

    @Test
    fun `nothing shows while a scan runs`() {
        assertEquals(StorageBanner.NONE, banner(scan(state = TelemetryState.FAILED), scanning = true, unsaved = true))
    }

    @Test
    fun `an unsaved in-memory result replaces the older clean scan as the latest`() {
        val clean = scan(id = 1L)
        val unsaved = scan(id = 2L, state = TelemetryState.FAILED)
        assertSame(unsaved, DashboardViewModel.resolveLatest(listOf(clean), unsaved))
        assertSame(clean, DashboardViewModel.resolveLatest(listOf(clean), null))
    }

    @Test
    fun `a result is unsaved exactly when no saved scan has its id`() {
        val r = scan(id = 2L)
        assertNull(DashboardViewModel.unsavedOrNull(r, listOf(scan(id = 2L), scan(id = 1L))))
        assertSame(r, DashboardViewModel.unsavedOrNull(r, listOf(scan(id = 1L))))
    }

    @Test
    fun `the health flag clears only after a scan that was saved with all its records`() {
        val saved = listOf(scan(id = 2L))
        assertTrue(DashboardViewModel.shouldClearHealthFlag(scan(id = 2L), saved))
        assertTrue(!DashboardViewModel.shouldClearHealthFlag(scan(id = 3L), saved))
        assertTrue(!DashboardViewModel.shouldClearHealthFlag(scan(id = 2L, state = TelemetryState.FAILED), saved))
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
