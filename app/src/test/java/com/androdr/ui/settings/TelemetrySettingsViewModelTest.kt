package com.androdr.ui.settings

import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.data.repo.SettingsRepository
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.TelemetryRetention
import com.androdr.scanner.WriterFixture
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.concurrent.Executors

/**
 * Settings' telemetry card (spec §8.2): storage by kind, "Keep snapshot telemetry for the last N
 * scans" (5..100, default 20), and "Delete old snapshot telemetry now", which runs the existing
 * retention path ([TelemetryRetention.run]) and refreshes the storage figures.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class TelemetrySettingsViewModelTest {
    private val w = WriterFixture()
    private val settings = SettingsRepository(w.f.dataStore)
    private val retention = TelemetryRetention(w.f.db, w.f.store, w.lock, w.f.dirty, settings)
    private val main = Executors.newSingleThreadExecutor()
    private val live = TelemetrySource.LIVE_SCAN

    // A real thread for viewModelScope: the store and DataStore resume on their own threads.
    @Before fun setUp() = Dispatchers.setMain(main.asCoroutineDispatcher())

    @After fun tearDown() {
        // Each test's view models stop here, so none outlives its store into the next test.
        created.forEach { it.viewModelScope.cancel() }
        Dispatchers.resetMain()
        main.shutdownNow()
        w.close()
    }

    private val created = mutableListOf<TelemetrySettingsViewModel>()

    private fun vm() = TelemetrySettingsViewModel(w.f.reader, settings, retention).also { created += it }

    private suspend fun liveScans(ids: LongRange) {
        for (id in ids) {
            val s = w.writer.begin(w.scan(id), liveEvents = true)
            s.append("app_scanner", live, CAPTURED, listOf(app("com.s$id")))
            s.finish()
        }
    }

    private fun state(id: Long): String = w.f.db.openHelper.readableDatabase
        .query("SELECT telemetryState FROM ScanResult WHERE id = $id").use { c -> c.moveToFirst(); c.getString(0) }

    private fun observations(scanId: Long) = w.count("SELECT COUNT(*) FROM scan_record WHERE scanId = $scanId")

    private suspend fun <T> await(block: suspend () -> T): T = withTimeout(10_000) { block() }

    @Test
    fun `storage is shown by kind`() = runBlocking {
        liveScans(1L..3L)
        val storage = await { vm().storage.filterNotNull().first() }
        assertEquals(3L, storage.snapshots.bodies)
        assertEquals(0L, storage.liveEvents.bodies)
        assertEquals(0L, storage.imports.bodies)
    }

    @Test
    fun `the slider keeps 20 scans by default and stores values clamped to 5 to 100`() = runBlocking {
        val vm = vm()
        assertEquals(20, vm.retentionScans.value)
        assertEquals(5..100, TelemetrySettingsViewModel.RETENTION_RANGE)
        // Each value is awaited on the view model's state (fed by the stored setting), then read back from
        // the store. (Hangs seen while writing this test came from earlier tests' view models outliving
        // their fixture; tearDown now cancels every view model's scope.)
        for ((asked, stored) in listOf(3 to 5, 250 to 100, 42 to 42)) {
            vm.setRetentionScans(asked)
            await { vm.retentionScans.first { it == stored } }
            assertEquals(stored, settings.snapshotRetentionScans.first())
        }
    }

    @Test
    fun `delete old snapshot telemetry now runs retention and refreshes storage`() = runBlocking {
        liveScans(1L..7L)
        settings.setSnapshotRetentionScans(5)
        val vm = vm()
        assertEquals(7L, await { vm.storage.filterNotNull().first() }.snapshots.bodies)

        vm.deleteOldSnapshotsNow()
        val done = await { vm.cleanup.first { it is TelemetryCleanup.Done } } as TelemetryCleanup.Done

        // The existing retention path ran: it marks each scan it trimmed PARTIAL_RETENTION.
        assertEquals(2L, done.observationsRemoved)
        assertEquals(listOf(TelemetryState.PARTIAL_RETENTION.name, TelemetryState.PARTIAL_RETENTION.name),
            listOf(state(1L), state(2L)))
        assertEquals(TelemetryState.STORED.name, state(3L))
        assertEquals(0L, observations(1L))
        assertEquals(0L, observations(2L))
        assertTrue((3L..7L).all { observations(it) == 1L })
        assertEquals(5L, await { vm.storage.first { it?.snapshots?.bodies == 5L } }!!.snapshots.bodies)
    }

    @Test
    fun `delete now while a scan holds the lock says so and removes nothing`() = runBlocking {
        liveScans(1L..7L)
        settings.setSnapshotRetentionScans(5)
        val vm = vm()
        w.lock.mutex.lock()
        try {
            vm.deleteOldSnapshotsNow()
            await { vm.cleanup.first { it == TelemetryCleanup.Busy } }
        } finally {
            w.lock.mutex.unlock()
        }
        assertTrue((1L..7L).all { observations(it) == 1L })
        vm.dismissCleanup()
        assertEquals(TelemetryCleanup.Idle, vm.cleanup.value)
    }
}
