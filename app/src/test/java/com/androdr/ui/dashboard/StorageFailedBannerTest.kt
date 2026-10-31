package com.androdr.ui.dashboard

import com.androdr.data.model.ScanWithFindings
import com.androdr.data.model.scanWith
import com.androdr.data.model.TelemetryState
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import com.androdr.data.store.StorageHealthFlag
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
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
        notSaved: Boolean = false,
    ) = DashboardViewModel.storageBanner(scan, scanning, unsaved, flag, notSaved)

    @Test
    fun `a saved FAILED scan says some records were not saved`() =
        assertEquals(StorageBanner.PARTLY_STORED, banner(scan(state = TelemetryState.FAILED)))

    /** D4 fix I1: retention trimming a FAILED scan must not hide that its storage failed. */
    @Test
    fun `a FAILED scan that retention trimmed still says some records were not saved`() =
        assertEquals(StorageBanner.PARTLY_STORED, banner(scan(state = TelemetryState.FAILED_PARTIAL_RETENTION)))

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

    /**
     * #418: a live scan that failed to save for a non-storage reason left only the in-memory result, so
     * after a restart the earlier saved scan read as the latest with no warning. The persistent
     * not-saved marker now survives the restart.
     */
    @Test
    fun `after a restart a non-storage save failure still says a recent scan is missing`() {
        assertEquals(StorageBanner.EARLIER_SCAN_NOT_SAVED, banner(scan(), notSaved = true))
        assertEquals("the storage cause wins when both are known", StorageBanner.EARLIER_SCAN_SHOWN,
            banner(scan(), flag = true, notSaved = true))
        assertEquals(StorageBanner.NOT_SAVED, banner(scan(), unsaved = true, notSaved = true))
        val strings = java.io.File("src/main/res/values/strings.xml").readText()
        val body = Regex("name=\"scan_not_saved_earlier_banner_body\">([^<]*)").find(strings)!!.groupValues[1]
        assertTrue("no storage cause is asserted", !body.contains("ran out") && !body.contains("storage"))
        assertTrue(body.contains("earlier"))
    }

    @Test
    fun `the Dashboard records every finished scan's outcome, uncancellably, and the screen renders it`() {
        fun src(path: String) = java.io.File(path).readText().replace(Regex("\\s+"), " ")
        val vm = src("src/main/java/com/androdr/ui/dashboard/DashboardViewModel.kt")
        assertTrue(vm.contains("withContext(NonCancellable) { storageHealth.recordScan("))
        assertTrue(src("src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt")
            .contains("R.string.scan_not_saved_earlier_banner_body"))
    }

    /**
     * Runs [block] over one DataStore file; each `newFlag()` closes the previous DataStore and opens a
     * new one on the same file, as a process restart does.
     */
    private fun withHealthStore(block: suspend (newFlag: suspend () -> StorageHealthFlag) -> Unit) = runBlocking {
        val dir = java.nio.file.Files.createTempDirectory("health").toFile()
        val jobs = mutableListOf<Job>()
        val newFlag: suspend () -> StorageHealthFlag = {
            jobs.lastOrNull()?.cancelAndJoin()
            val job = SupervisorJob().also { jobs += it }
            StorageHealthFlag(
                PreferenceDataStoreFactory.create(scope = CoroutineScope(Dispatchers.IO + job)) {
                    java.io.File(dir, "h.preferences_pb")
                },
            )
        }
        try {
            block(newFlag)
        } finally {
            jobs.forEach { it.cancel() }
            dir.deleteRecursively()
        }
    }

    @Test
    fun `the not-saved marker survives a restart and a fully stored scan clears it`() = withHealthStore { newFlag ->
        newFlag().recordScan(saved = false, fullyStored = false)
        val reopened = newFlag()
        assertTrue("survives reopening the DataStore", reopened.scanNotSavedFlow.first())
        assertTrue("the storage flag is separate", !reopened.isSet())
        reopened.recordScan(saved = true, fullyStored = true)
        assertTrue(!reopened.scanNotSavedFlow.first())
    }

    /** Review fix: a later saved-but-partly-stored scan must not be called "an earlier scan". */
    @Test
    fun `an unsaved scan then a saved partly stored scan shows the partly stored banner`() =
        withHealthStore { newFlag ->
            val flag = newFlag()
            flag.recordScan(saved = false, fullyStored = false)
            flag.recordScan(saved = true, fullyStored = false)
            val latest = scan(id = 2L, state = TelemetryState.FAILED)
            assertEquals(StorageBanner.PARTLY_STORED,
                banner(latest, flag = flag.isSet(), notSaved = flag.scanNotSavedFlow.first()))
        }

    @Test
    fun `a saved scan with missing records keeps the storage flag`() = withHealthStore { newFlag ->
        val flag = newFlag()
        flag.set()
        flag.recordScan(saved = true, fullyStored = false)
        assertTrue(flag.isSet())
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
        // #418 re-gate: a FAILED scan later trimmed by retention is still not fully stored.
        val failedTrimmed = scan(id = 2L, state = TelemetryState.FAILED_PARTIAL_RETENTION)
        assertTrue(!DashboardViewModel.shouldClearHealthFlag(failedTrimmed, saved = true))
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
