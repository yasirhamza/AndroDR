package com.androdr.data.db

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.SignalMember
import com.androdr.data.model.TelemetryState
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.TimelineRowDeleter
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.StoreFixture.Companion.app
import io.mockk.coEvery
import io.mockk.spyk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * C3 (spec §5.3): the one-time cleanup of the retired event adapters' rows. It selects by
 * PRODUCER (`source`), never by category, only in scans whose telemetry is in the store
 * (`STORED`, `PARTIAL_RETENTION`), and skips rows a live signal still lists as a member; orphaned
 * member refs (their signal row is gone) are removed first, so they protect nothing.
 */
@RunWith(RobolectricTestRunner::class)
class LegacyEventRowCleanupTest {
    private val f = StoreFixture()
    private val lock = ScanLock()
    private var rows = TimelineRowDeleter(f.db.forensicTimelineEventDao(), f.store, f.db.signalMemberDao())

    @After fun tearDown() = f.close()

    private fun cleanup() = LegacyEventRowCleanup(
        f.db, rows, f.db.signalMemberDao(), f.store, lock, f.dataStore,
    )

    private suspend fun scan(id: Long, telemetry: TelemetryState) {
        f.db.scanResultDao().insert(ScanResult(id = id, timestamp = id, findings = emptyList(),
            bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0,
            state = ScanState.COMPLETE, telemetryState = telemetry))
    }

    private fun row(source: String, scan: Long, category: String = "c", kind: String = "event", ruleId: String = "") =
        ForensicTimelineEvent(startTimestamp = 1L, source = source, category = category, description = source,
            scanResultId = scan, kind = kind, ruleId = ruleId)

    private suspend fun insert(vararg r: ForensicTimelineEvent): List<Long> =
        f.db.forensicTimelineEventDao().insertAll(r.toList())

    private fun left(): List<Pair<String, Long>> = f.db.openHelper.readableDatabase
        .query("SELECT source, scanResultId FROM forensic_timeline ORDER BY id").use { c ->
            generateSequence { if (c.moveToNext()) c.getString(0) to c.getLong(1) else null }.toList()
        }

    @Test
    fun `deletes every retired producer's rows in STORED and PARTIAL_RETENTION scans, keeps NONE and FAILED`() =
        runBlocking {
            scan(1L, TelemetryState.STORED)
            scan(2L, TelemetryState.PARTIAL_RETENTION)
            scan(3L, TelemetryState.NONE)
            scan(4L, TelemetryState.FAILED)
            for (scan in 1L..4L) {
                insert(*LegacyEventRowCleanup.RETIRED_SOURCES.map { row(it, scan) }.toTypedArray())
            }

            val outcome = cleanup().run()

            assertEquals(2 * LegacyEventRowCleanup.RETIRED_SOURCES.size, outcome.deleted)
            assertTrue(outcome.completed)
            assertEquals("pre-feature and evaluate-only scans keep their only record",
                setOf(3L, 4L), left().map { it.second }.toSet())
            assertEquals(2 * LegacyEventRowCleanup.RETIRED_SOURCES.size, left().size)
        }

    @Test
    fun `the frozen producer list is exactly the retired event adapters`() {
        assertEquals(
            setOf("intrusion_log", "usage_stats", "appops", "battery_daily", "adb_audit", "bugreport"),
            LegacyEventRowCleanup.RETIRED_SOURCES.toSet(),
        )
    }

    @Test
    fun `live detected changes, finding rows, signals and persistent rows survive in a STORED scan`() =
        runBlocking {
            scan(1L, TelemetryState.STORED)
            insert(
                // InstallEventEmitter / DeviceAdminGrantEmitter: same categories as retired rows.
                row("app_scanner", 1L, category = "package_install"),
                row("device_admin_emitter", 1L, category = "device_admin_grant"),
                row("intrusion_log_analysis", 1L, ruleId = "androdr-1"),
                row("bugreport_analysis", 1L, ruleId = "androdr-2"),
                row("sigma_correlation_engine", 1L, kind = "signal"),
                // A retired producer's package_install row (InstallTimeModule) goes, by source.
                row("bugreport", 1L, category = "package_install"),
            )

            cleanup().run()

            assertEquals(listOf("app_scanner", "device_admin_emitter", "intrusion_log_analysis",
                "bugreport_analysis", "sigma_correlation_engine"), left().map { it.first })
        }

    @Test
    fun `an intrusion-log row a live signal references survives`() = runBlocking {
        scan(1L, TelemetryState.STORED)
        val (referenced, plain, signal) = insert(row("intrusion_log", 1L), row("intrusion_log", 1L),
            row("sigma_correlation_engine", 1L, kind = "signal"))
        f.db.signalMemberDao().insertAll(listOf(SignalMember(signal, SignalMember.KIND_ROW, referenced)))

        cleanup().run()

        val ids = f.db.openHelper.readableDatabase.query("SELECT id FROM forensic_timeline ORDER BY id").use { c ->
            generateSequence { if (c.moveToNext()) c.getLong(0) else null }.toList()
        }
        assertEquals(listOf(referenced, signal), ids)
        assertFalse(plain in ids)
        assertEquals(1L, f.count("SELECT COUNT(*) FROM signal_member"))
    }

    @Test
    fun `orphaned member refs are removed, release their facts and protect nothing`() = runBlocking {
        scan(1L, TelemetryState.STORED)
        val (row) = insert(row("intrusion_log", 1L))
        // A fact pinned only by an orphaned member (no observation left).
        f.scan(5L, ScanState.COMPLETE)
        val fact = f.persist(5L, "app_scanner", listOf(app("com.orphan"))).factIdByChunkIndex.single()
        f.db.signalMemberDao().insertAll(listOf(
            SignalMember(404L, SignalMember.KIND_ROW, row), SignalMember(404L, SignalMember.KIND_FACT, fact),
        ))
        f.store.deleteScanTelemetry(5L)
        assertEquals("the orphaned member pins it", 1L, f.count("SELECT COUNT(*) FROM telemetry_record"))

        val outcome = cleanup().run()

        assertEquals(1, outcome.orphanSignals)
        assertEquals(0L, f.count("SELECT COUNT(*) FROM signal_member"))
        assertEquals("the row it listed is no longer protected", 0L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
        assertEquals("its fact pin is released", 0L, f.count("SELECT COUNT(*) FROM telemetry_record"))
    }

    @Test
    fun `runs in batches, once`() = runBlocking {
        scan(1L, TelemetryState.STORED)
        val total = LegacyEventRowCleanup.BATCH * 2 + 7
        insert(*(1..total).map { row("usage_stats", 1L) }.toTypedArray())

        val first = cleanup().run()
        assertEquals(total, first.deleted)
        assertEquals(0L, f.count("SELECT COUNT(*) FROM forensic_timeline"))

        insert(row("usage_stats", 1L))
        val second = cleanup().run()
        assertFalse("a done cleanup does not run again", second.completed)
        assertEquals(1L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
    }

    @Test
    fun `a failing batch is logged and counted, never thrown, and the next launch finishes`() = runBlocking {
        scan(1L, TelemetryState.STORED)
        insert(row("intrusion_log", 1L))
        val failing = spyk(rows)
        coEvery { failing.byIds(any()) } throws IllegalStateException("disk I/O")
        rows = failing

        val broken = cleanup().run()

        assertEquals(1, broken.failed)
        assertFalse("not marked done", broken.completed)
        assertEquals(1L, f.count("SELECT COUNT(*) FROM forensic_timeline"))

        rows = TimelineRowDeleter(f.db.forensicTimelineEventDao(), f.store, f.db.signalMemberDao())
        val retried = cleanup().run()
        assertTrue(retried.completed)
        assertEquals(0L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
    }

    @Test
    fun `each batch waits for the scan lock`() = runBlocking {
        scan(1L, TelemetryState.STORED)
        insert(row("intrusion_log", 1L))
        lock.mutex.lock()
        val job = async(Dispatchers.IO) { cleanup().run() }
        delay(200)
        assertEquals("nothing deleted while a writer holds the lock", 1L,
            f.count("SELECT COUNT(*) FROM forensic_timeline"))
        lock.mutex.unlock()
        withTimeout(5_000) { job.await() }
        assertEquals(0L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
    }
}
