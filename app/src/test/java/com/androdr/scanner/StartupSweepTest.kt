package com.androdr.scanner

import androidx.room.withTransaction
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.ScanWriteRepository
import com.androdr.data.db.SignalMemberBackfill
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.scanner.WriterFixture.Companion.EVIL_DOMAIN
import com.androdr.scanner.WriterFixture.Companion.IMPORT_CAPTURED
import com.androdr.scanner.WriterFixture.Companion.securityLine
import io.mockk.coEvery
import io.mockk.spyk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.nio.file.Files
import com.androdr.reporting.ReportFiles
import com.androdr.data.repo.ScanRepository

/** S3 / Review Focus 5: the startup sweep, the writer lock, the dirty flag and scan deletion. */
@RunWith(RobolectricTestRunner::class)
class StartupSweepTest {
    private val w = WriterFixture()

    @After fun tearDown() {
        w.close()
        reportsDir.deleteRecursively()
    }

    private val reportsDir: File = Files.createTempDirectory("reports").toFile()
    private val clock = 10L * 24 * 60 * 60 * 1000

    private fun sweep(repo: ScanWriteRepository = w.repo) =
        StartupSweep(w.lock, repo, w.f.store, w.f.dirty, ReportFiles(reportsDir) { clock },
            SignalMemberBackfill(w.f.db, w.f.db.signalMemberBackfillDao(), w.f.db.signalMemberDao(), w.lock,
                w.f.dataStore))

    private fun state(id: Long): String? = w.f.db.openHelper.readableDatabase
        .query("SELECT state FROM ScanResult WHERE id = $id").use { c -> if (c.moveToFirst()) c.getString(0) else null }

    /** An orphan fact: stored, then its only observation removed behind the store's back. */
    private suspend fun orphanFact() {
        w.f.scan(99L)
        w.f.persist(99L, "app_scanner", listOf(app("com.orphan")))
        w.f.db.openHelper.writableDatabase.execSQL("DELETE FROM scan_record WHERE scanId = 99")
        w.f.db.openHelper.writableDatabase.execSQL("DELETE FROM ScanResult WHERE id = 99")
    }

    @Test
    fun `a killed writer stays IN_PROGRESS and the sweep removes it with one interrupted row per import`() =
        runBlocking {
            // A killed intrusion-log import, a killed live scan, an interrupted delete, a finished scan.
            val import = w.writer.begin(w.scan(1L, TelemetrySource.INTRUSION_LOG_IMPORT), liveEvents = false)
            import.append("security_log", TelemetrySource.INTRUSION_LOG_IMPORT, IMPORT_CAPTURED, listOf(securityLine()))
            val liveScan = w.writer.begin(w.scan(2L), liveEvents = true)
            liveScan.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED, listOf(dns(EVIL_DOMAIN)))
            val done = w.writer.begin(w.scan(4L), liveEvents = false)
            done.append("app_scanner", TelemetrySource.LIVE_SCAN, CAPTURED, listOf(app("com.kept")))
            done.finish()
            val deleting = w.scan(3L, TelemetrySource.INTRUSION_LOG_IMPORT).copy(state = ScanState.DELETING)
            w.f.db.scanResultDao().insert(deleting)
            assertEquals("IN_PROGRESS", state(1L))
            assertEquals("IN_PROGRESS", state(2L))

            assertEquals(3, sweep().run())

            assertEquals(listOf(null, null, null, "COMPLETE"), (1L..4L).map { state(it) })
            val interrupted = w.f.db.forensicTimelineEventDao().getAllForExport()
                .filter { it.category == StartupSweep.CATEGORY }
            assertEquals(1, interrupted.size)
            assertTrue(interrupted.single().persistent)
            assertEquals(TelemetrySource.INTRUSION_LOG_IMPORT, interrupted.single().telemetrySource)
            assertEquals(-1L, interrupted.single().scanResultId)
            assertEquals("only the finished scan's fact is left", 1L, w.count("SELECT COUNT(*) FROM telemetry_record"))
            assertEquals(1L, w.visibleFacts())
        }

    @Test
    fun `the sweep runs gc only when it swept something or the dirty flag is set`() = runBlocking {
        orphanFact()
        assertEquals(0, sweep().run())
        assertEquals("nothing swept, flag clear: no gc", 1L, w.count("SELECT COUNT(*) FROM telemetry_record"))

        w.f.scan(5L, ScanState.IN_PROGRESS)
        assertEquals(1, sweep().run())
        assertEquals("swept something: gc ran", 0L, w.count("SELECT COUNT(*) FROM telemetry_record"))
    }

    @Test
    fun `dirty flag - a failed delete batch sets it and the next sweep gcs with nothing to sweep and clears it`() =
        runBlocking {
            w.f.scan(1L)
            w.f.persist(1L, "app_scanner", listOf(app("com.a")))
            val failing = spyk(w.f.store)
            coEvery { failing.deleteBatch(any(), any()) } throws IllegalStateException("disk went away")
            assertTrue(runCatching { failing.deleteScanTelemetry(1L) }.isFailure)
            assertTrue(w.f.dirty.isSet())
            w.f.setState(1L, ScanState.COMPLETE)
            orphanFact()

            assertEquals(0, sweep().run())
            assertFalse(w.f.dirty.isSet())
            assertEquals("the orphan is gone, scan 1's fact stays", 1L,
                w.count("SELECT COUNT(*) FROM telemetry_record"))
        }

    @Test
    fun `a target that fails is logged, sets the dirty flag, and the other targets are still swept`() = runBlocking {
        w.f.scan(1L, ScanState.IN_PROGRESS)
        w.f.scan(2L, ScanState.IN_PROGRESS)
        val repo = spyk(w.repo)
        coEvery { repo.completeDelete(1L) } throws IllegalStateException("cannot delete 1")
        assertEquals(1, sweep(repo).run())
        assertEquals("left for the next start", "IN_PROGRESS", state(1L))
        assertEquals(null, state(2L))
        assertFalse("gc ran after the failure and cleared the flag", w.f.dirty.isSet())
    }

    @Test
    fun `the sweep deletes stale report and export files and keeps fresh ones`() = runBlocking {
        val stale = File(reportsDir, "androdr_report_old.txt").apply { writeText("x") }
        val fresh = File(reportsDir, "androdr_timeline_new.csv").apply { writeText("y") }
        stale.setLastModified(clock - ReportFiles.STALE_AFTER_MS - 1)
        fresh.setLastModified(clock - 1_000)
        sweep().run()
        assertFalse(stale.exists())
        assertTrue(fresh.exists())
    }

    @Test
    fun `a scan started during the sweep survives it`() = runBlocking {
        w.f.scan(1L, ScanState.IN_PROGRESS)
        val repo = spyk(w.repo)
        coEvery { repo.completeDelete(1L) } coAnswers {
            // The sweep released the lock after its snapshot: a new session can begin now.
            w.lock.withWriter { w.writer.begin(w.scan(2L), liveEvents = false) }
            // The real (unspied) repo, not MockK's callOriginal: see CoAnswersCallOriginalTest.
            w.repo.completeDelete(1L)
        }
        assertEquals(1, sweep(repo).run())
        assertEquals(null, state(1L))
        assertEquals("IN_PROGRESS", state(2L))
    }

    @Test
    fun `ScanLock - writerRunning is true inside withWriter and false after a block that throws`() = runBlocking {
        val lock = ScanLock()
        assertFalse(lock.writerRunning.value)
        lock.withWriter { assertTrue(lock.writerRunning.value) }
        assertFalse(lock.writerRunning.value)
        assertTrue(runCatching { lock.withWriter { error("writer failed") } }.isFailure)
        assertFalse(lock.writerRunning.value)
        assertFalse(lock.mutex.isLocked)
    }

    @Test
    fun `ScanLock - a lock-then-transaction batch waits for the writer and then completes`() = runBlocking {
        val release = CompletableDeferred<Unit>()
        val writerIn = CompletableDeferred<Unit>()
        val writer = async(Dispatchers.IO) {
            w.lock.withWriter {
                writerIn.complete(Unit)
                release.await()
            }
        }
        writerIn.await()
        val batch = async(Dispatchers.IO) {
            w.lock.mutex.withLock {
                w.f.db.withTransaction {
                    w.f.db.forensicTimelineEventDao().insert(
                        ForensicTimelineEvent(startTimestamp = 1L, source = "backfill", category = "c",
                            description = "d"))
                }
            }
        }
        repeat(20) { yield() }
        assertFalse("the batch waits for the writer", batch.isCompleted)
        assertTrue(w.lock.writerRunning.value)
        release.complete(Unit)
        withTimeout(10_000) {
            writer.await()
            batch.await()
        }
        assertFalse(w.lock.writerRunning.value)
        assertEquals(1L, w.count("SELECT COUNT(*) FROM forensic_timeline WHERE source = 'backfill'"))
    }

    // ── ScanRepository deletes ──────────────────────────────────────────────────

    private fun scanRepository(lock: ScanLock = w.lock) = ScanRepository(
        scanResultDao = w.f.db.scanResultDao(), dnsEventDao = w.f.db.dnsEventDao(),
        forensicTimelineEventDao = w.f.db.forensicTimelineEventDao(),
        indicatorResolver = io.mockk.mockk(relaxed = true),
        scanWrites = w.repo,
        scanLock = lock,
    )

    @Test
    fun `deleteScan removes the scan, its rows and its telemetry, keeping persistent rows`() = runBlocking {
        val s = w.writer.begin(w.scan(1L), liveEvents = false)
        s.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED, listOf(dns(EVIL_DOMAIN), dns("ok.example")))
        s.finish()
        w.f.db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = 1L, source = "audit",
            category = "scan_deleted", description = "kept", scanResultId = 1L, persistent = true))
        assertEquals(1L, w.count("SELECT COUNT(*) FROM forensic_timeline WHERE recordId IS NOT NULL"))

        assertTrue(scanRepository().deleteScan(1L))
        assertEquals(null, state(1L))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM telemetry_record"))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM record_body"))
        assertEquals(listOf("kept"), w.f.db.forensicTimelineEventDao().getAllForExport().map { it.description })
    }

    @Test
    fun `clear-all - a writer that begins after the first phase completes with its data intact`() = runBlocking {
        val old = w.writer.begin(w.scan(1L), liveEvents = false)
        old.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED, listOf(dns(EVIL_DOMAIN, time = 1L)))
        old.finish()
        val snapshot = w.lock.mutex.withLock { w.repo.markAllForDelete() }
        // The writer takes the lock after "Clear all" released it, before its second phase runs.
        val s = w.lock.withWriter {
            w.writer.begin(w.scan(2L), liveEvents = false).also {
                it.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED, listOf(dns(EVIL_DOMAIN, time = 2L)))
            }
        }
        w.repo.completeDeleteAll(snapshot)
        val r = s.finish()
        assertEquals(listOf(1L), snapshot)
        assertEquals(null, state(1L))
        assertEquals("COMPLETE", state(2L))
        assertEquals(1, r.scan.findings.size)
        assertEquals(1L, w.count("SELECT COUNT(*) FROM scan_record WHERE scanId = 2"))
        assertEquals(1L, w.count("SELECT COUNT(*) FROM forensic_timeline WHERE scanResultId = 2"))
        assertEquals(1L, w.visibleFacts())
    }

    @Test
    fun `a delete waiting on a lock held by a non-writer gives up, changes nothing and leaves no lock`() =
        runBlocking {
            val s = w.writer.begin(w.scan(1L), liveEvents = false)
            s.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED, listOf(dns(EVIL_DOMAIN)))
            s.finish()
            val repo = scanRepository().apply { deleteLockWaitMs = 150L }
            val owner = Any()
            w.lock.mutex.lock(owner) // e.g. a retention or backfill batch: writerRunning stays false
            assertFalse(w.lock.writerRunning.value)
            assertFalse(repo.deleteScan(1L))
            assertFalse(repo.deleteAllScans())
            assertEquals("COMPLETE", state(1L))
            assertTrue("still held by its owner only", w.lock.mutex.holdsLock(owner))
            w.lock.mutex.unlock(owner)
            assertFalse("the refused deletes left no lock behind", w.lock.mutex.isLocked)
            assertTrue(repo.deleteScan(1L))
            assertFalse(w.lock.mutex.isLocked)
            assertEquals(null, state(1L))
        }

    @Test
    fun `deleteAllScans clears every scan but persistent rows, and both refuse while a writer runs`() = runBlocking {
        for (id in 1L..2L) {
            val s = w.writer.begin(w.scan(id), liveEvents = false)
            s.append("dns_monitor", TelemetrySource.LIVE_SCAN, CAPTURED, listOf(dns(EVIL_DOMAIN, time = id)))
            s.finish()
        }
        w.f.db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = 1L, source = "audit",
            category = "scan_deleted", description = "kept", persistent = true))
        val repo = scanRepository()
        w.lock.withWriter {
            assertFalse(repo.deleteScan(1L))
            assertFalse(repo.deleteAllScans())
        }
        assertEquals("COMPLETE", state(1L))
        assertTrue(repo.deleteAllScans())
        assertEquals(0L, w.count("SELECT COUNT(*) FROM ScanResult"))
        assertEquals(0L, w.count("SELECT COUNT(*) FROM telemetry_record"))
        assertEquals(listOf("kept"), w.f.db.forensicTimelineEventDao().getAllForExport().map { it.description })
    }

    /** Spec §5.4: the one-time signal_member backfill runs from the startup sweep. */
    @Test
    fun `the sweep runs the signal member backfill once`() = runBlocking {
        val legacy = w.f.db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = 1L,
            kind = "signal", source = "sigma_correlation_engine", category = "correlation", description = "chain",
            ruleId = "androdr-corr-001", details = """{"rule_id":"androdr-corr-001","member_event_ids":"3,5"}"""))

        sweep().run()

        assertEquals(listOf(3L, 5L),
            w.f.db.signalMemberDao().forSignal(legacy, null, null, 10).map { it.refId })
    }
}
