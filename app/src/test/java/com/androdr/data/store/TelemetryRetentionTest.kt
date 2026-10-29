package com.androdr.data.store

import com.androdr.data.db.PinnedFact
import com.androdr.data.db.VisibleFact
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.data.repo.SettingsRepository
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.scanner.WriterFixture
import com.androdr.scanner.WriterFixture.Companion.EVIL_APP
import com.androdr.scanner.WriterFixture.Companion.EVIL_DOMAIN
import com.androdr.scanner.WriterFixture.Companion.IMPORT_CAPTURED
import com.androdr.scanner.WriterFixture.Companion.securityLine
import com.androdr.sigma.StoreRecord
import io.mockk.coEvery
import io.mockk.spyk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Retention (spec §5.1 Retention, §9 S3): snapshot observations are kept for the newest N live scans,
 * live event observations for 30 days, imports until deleted, pinned facts always; a scan that loses
 * observations becomes `PARTIAL_RETENTION`. Each batch is one transaction under `scanMutex.tryLock()`.
 */
@RunWith(RobolectricTestRunner::class)
class TelemetryRetentionTest {
    private val w = WriterFixture()
    private val settings = SettingsRepository(w.f.dataStore)
    private var retention = TelemetryRetention(w.f.db, w.f.store, w.lock, w.f.dirty, settings)
    private val live = TelemetrySource.LIVE_SCAN
    private val il = TelemetrySource.INTRUSION_LOG_IMPORT

    @After fun tearDown() = w.close()

    private companion object {
        const val DAY = 24L * 60 * 60 * 1000
        const val NOW = 1_800_000_000_000L
        const val OLD_EVENT = NOW - 31 * DAY
        const val RECENT_EVENT = NOW - 29 * DAY
    }

    private suspend fun liveScan(id: Long, apps: List<StoreRecord>, dnsRecords: List<StoreRecord> = emptyList()) {
        val s = w.writer.begin(w.scan(id), liveEvents = true)
        s.append("app_scanner", live, CAPTURED, apps)
        if (dnsRecords.isNotEmpty()) s.append("dns_monitor", live, CAPTURED, dnsRecords)
        s.finish()
    }

    private suspend fun intrusionLog(id: Long, time: Long) {
        val s = w.writer.begin(w.scan(id, il), liveEvents = false)
        s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine(time = time)))
        s.finish()
    }

    private fun state(id: Long): String = w.f.db.openHelper.readableDatabase
        .query("SELECT telemetryState FROM ScanResult WHERE id = $id").use { c -> c.moveToFirst(); c.getString(0) }

    private fun observations(scanId: Long, where: String = "1") =
        w.count("SELECT COUNT(*) FROM scan_record WHERE scanId = $scanId AND $where")

    private fun factOf(pkg: String): Long = w.count(
        "SELECT o.recordId FROM scan_record o WHERE o.service = 'app_scanner' AND o.recordId IN " +
            "(SELECT id FROM telemetry_record WHERE packageName = '$pkg') LIMIT 1")

    /** No fact is left with no observation and no pin, and no body is left that no fact uses. */
    private fun assertNoUnpinnedOrphan() {
        assertEquals("unpinned orphan fact", 0L, w.count(
            "SELECT COUNT(*) FROM telemetry_record f WHERE ${PinnedFact.UNOBSERVED} AND NOT ${PinnedFact.SQL}"))
        assertEquals("unreferenced body", 0L, w.count("SELECT COUNT(*) FROM record_body b WHERE NOT EXISTS " +
            "(SELECT 1 FROM telemetry_record t WHERE t.bodyHash = b.hash)"))
    }

    /** 25 live scans (ids 1..25, each with one app of its own and one shared app) and 2 newer imports. */
    private suspend fun twentyFiveLiveScansAndTwoImports() {
        for (id in 1L..25L) liveScan(id, listOf(app("com.shared"), app("com.s$id")))
        intrusionLog(1_001L, OLD_EVENT)
        intrusionLog(1_002L, OLD_EVENT - DAY)
    }

    @Test
    fun `snapshots are kept for the newest 20 live scans, imports do not count and are untouched`() = runBlocking {
        twentyFiveLiveScansAndTwoImports()
        val importObservations = observations(1_001L) + observations(1_002L)

        val outcome = retention.run(NOW)

        assertTrue(outcome.completed)
        for (id in 1L..5L) {
            assertEquals("scan $id lost its snapshots", 0L, observations(id))
            assertEquals(TelemetryState.PARTIAL_RETENTION.name, state(id))
            assertEquals("its own app fact is gone", 0L,
                w.count("SELECT COUNT(*) FROM telemetry_record WHERE packageName = 'com.s$id'"))
        }
        for (id in 6L..25L) {
            assertEquals("scan $id keeps its snapshots", 2L, observations(id))
            assertEquals(TelemetryState.STORED.name, state(id))
        }
        assertEquals("imports untouched, old events included", importObservations,
            observations(1_001L) + observations(1_002L))
        assertEquals(TelemetryState.STORED.name, state(1_001L))
        assertEquals(TelemetryState.STORED.name, state(1_002L))
        assertEquals("the shared fact stays", 1L,
            w.count("SELECT COUNT(*) FROM telemetry_record WHERE packageName = 'com.shared'"))
        assertNoUnpinnedOrphan()
    }

    @Test
    fun `the snapshot count follows the setting`() = runBlocking {
        for (id in 1L..4L) liveScan(id, listOf(app("com.s$id")))
        settings.setSnapshotRetentionScans(2)
        retention.run(NOW)
        assertEquals(listOf(0L, 0L, 1L, 1L), (1L..4L).map { observations(it) })
    }

    /** A trimmed `FAILED` scan keeps the failure and records that retention trimmed it (D4 fix I1). */
    @Test
    fun `a FAILED scan that retention trims becomes FAILED_PARTIAL_RETENTION`() = runBlocking {
        for (id in 1L..2L) liveScan(id, listOf(app("com.s$id")))
        w.f.db.openHelper.writableDatabase.execSQL("UPDATE ScanResult SET telemetryState = 'FAILED' WHERE id = 1")
        settings.setSnapshotRetentionScans(1)
        retention.run(NOW)
        assertEquals(0L, observations(1L))
        assertEquals(TelemetryState.FAILED_PARTIAL_RETENTION.name, state(1L))
    }

    @Test
    fun `live events older than 30 days are trimmed and their scans become PARTIAL_RETENTION`() = runBlocking {
        liveScan(1L, listOf(app("com.a")), listOf(dns("old.example", time = OLD_EVENT, key = "dns:1")))
        liveScan(2L, listOf(app("com.a")), listOf(dns("recent.example", time = RECENT_EVENT, key = "dns:2")))

        retention.run(NOW)

        assertEquals("the old event's observation goes", 0L, observations(1L, "eventTime IS NOT NULL"))
        assertEquals("the scan's snapshots stay (it is among the newest 20)", 1L, observations(1L))
        assertEquals(TelemetryState.PARTIAL_RETENTION.name, state(1L))
        assertEquals("the old unpinned event fact is gone", 0L, w.count(
            "SELECT COUNT(*) FROM telemetry_record WHERE service = 'dns_monitor' AND eventTime = $OLD_EVENT"))
        assertEquals(1L, observations(2L, "eventTime IS NOT NULL"))
        assertEquals(TelemetryState.STORED.name, state(2L))
        assertNoUnpinnedOrphan()
    }

    @Test
    fun `pinned facts survive retention and decode, imports are untouched`() = runBlocking {
        // Scan 1: a triggered state finding pins EVIL_APP's fact; an old IOC DNS event opens an alert.
        liveScan(1L, listOf(app(EVIL_APP), app("com.bysignal"), app("com.bytimeline")),
            listOf(dns(EVIL_DOMAIN, time = OLD_EVENT, key = "dns:7")))
        w.f.pinBySignal(factOf("com.bysignal"))
        w.f.pinByTimeline(factOf("com.bytimeline"))
        intrusionLog(2L, OLD_EVENT)
        val importFacts = observations(2L)
        settings.setSnapshotRetentionScans(1)
        liveScan(3L, listOf(app("com.newer")))

        retention.run(NOW)

        assertEquals("scan 1 lost every observation", 0L, observations(1L))
        assertEquals(importFacts, observations(2L))
        val pinned = w.f.db.openHelper.readableDatabase.query(
            "SELECT f.id FROM telemetry_record f WHERE ${PinnedFact.UNOBSERVED} AND ${VisibleFact.SQL}"
        ).use { c -> buildList { while (c.moveToNext()) add(c.getLong(0)) } }
        val decoded = w.f.reader.records(pinned)
        assertEquals(setOf(EVIL_APP, "com.bysignal", "com.bytimeline"),
            decoded.mapNotNull { it.fields?.get("package_name") as? String }.toSet())
        val alertFact = w.count("SELECT recordId FROM alert")
        val dnsRecord = w.f.reader.records(listOf(alertFact)).single()
        assertEquals("the alert's matched fact decodes", EVIL_DOMAIN, dnsRecord.fields?.get("domain"))
        assertEquals(live, dnsRecord.source)
        assertEquals(DecodedRecord.ORPHAN.toLong(), dnsRecord.scanId)
        assertNoUnpinnedOrphan()
    }

    @Test
    fun `retention skips the cycle while a scan holds scanMutex`() = runBlocking {
        for (id in 1L..3L) liveScan(id, listOf(app("com.s$id")))
        settings.setSnapshotRetentionScans(1)
        w.lock.mutex.lock()
        val held = retention.run(NOW)
        assertFalse(held.completed)
        assertEquals(listOf(1L, 1L, 1L), (1L..3L).map { observations(it) })
        assertEquals(TelemetryState.STORED.name, state(1L))
        w.lock.mutex.unlock()

        assertTrue(retention.run(NOW).completed)
        assertEquals(listOf(0L, 0L, 1L), (1L..3L).map { observations(it) })
    }

    /** S3: a kill between retention batches leaves no visible orphan; the next cycle completes it. */
    @Test
    fun `a kill between batches leaves no unpinned orphan and a consistent scan state`() = runBlocking {
        liveScan(1L, (0 until 1_200).map { app("com.old$it") })
        liveScan(2L, listOf(app("com.new")))
        settings.setSnapshotRetentionScans(1)
        val spy = spyk(retention)
        var batches = 0
        coEvery { spy.batch(any(), TelemetryRetention.Phase.SNAPSHOTS, any()) } coAnswers {
            check(++batches != 2) { "killed between batches" }
            callOriginal()
        }

        assertTrue(runCatching { spy.run(NOW) }.isFailure)

        assertEquals("one batch of ${TelemetryRetention.BATCH} committed", 1_200L - TelemetryRetention.BATCH,
            observations(1L))
        assertEquals("the scan that lost observations says so", TelemetryState.PARTIAL_RETENTION.name, state(1L))
        assertNoUnpinnedOrphan()
        assertTrue("a failed batch marks the store dirty", w.f.dirty.isSet())

        assertTrue(retention.run(NOW).completed)
        assertEquals(0L, observations(1L))
        assertNoUnpinnedOrphan()
    }

    @Test
    fun `a retention batch that throws sets StoreDirtyFlag and rolls back`() = runBlocking {
        for (id in 1L..2L) liveScan(id, listOf(app("com.s$id")))
        settings.setSnapshotRetentionScans(1)
        w.f.db.openHelper.writableDatabase.execSQL(
            "CREATE TEMP TRIGGER boom BEFORE DELETE ON scan_record BEGIN SELECT RAISE(ABORT, 'boom'); END")
        assertFalse(w.f.dirty.isSet())

        assertTrue(runCatching { retention.run(NOW) }.isFailure)

        assertTrue(w.f.dirty.isSet())
        assertEquals("the batch rolled back", 1L, observations(1L))
        assertEquals(TelemetryState.STORED.name, state(1L))
        assertFalse("the lock is released", w.lock.mutex.isLocked)
    }

    /** Review m7: a scan taking the lock mid-cycle stops it after partial progress; the next cycle resumes. */
    @Test
    fun `a lock taken mid-cycle stops the cycle and the next cycle finishes the work`() = runBlocking {
        for (id in 1L..3L) liveScan(id, listOf(app("com.s$id")))
        settings.setSnapshotRetentionScans(1)
        val spy = spyk(retention)
        var calls = 0
        coEvery { spy.batch(any(), TelemetryRetention.Phase.SNAPSHOTS, any()) } coAnswers {
            if (++calls == 2) w.lock.mutex.lock() // a scan starts after the first snapshot batch
            callOriginal()
        }

        val first = spy.run(NOW)

        assertFalse(first.completed)
        assertEquals("scan 2 was trimmed before the lock was taken; scan 1 was not reached",
            listOf(1L, 0L, 1L), (1L..3L).map { observations(it) })
        assertEquals(TelemetryState.PARTIAL_RETENTION.name, state(2L))
        assertEquals(TelemetryState.STORED.name, state(1L))
        assertNoUnpinnedOrphan()
        w.lock.mutex.unlock()

        assertTrue(retention.run(NOW).completed)
        assertEquals(listOf(0L, 0L, 1L), (1L..3L).map { observations(it) })
        assertNoUnpinnedOrphan()
    }

    /** Review m7: a batch that reaches a scan the user marked DELETING leaves nothing the delete cannot finish. */
    @Test
    fun `a retention batch on a scan that turned DELETING leaves no orphan and the delete completes`() =
        runBlocking {
            liveScan(1L, listOf(app(EVIL_APP)) + (0 until 600).map { app("com.old$it") })
            liveScan(2L, listOf(app("com.new")))
            settings.setSnapshotRetentionScans(1)
            val spy = spyk(retention)
            var marked = false
            coEvery { spy.batch(1L, TelemetryRetention.Phase.SNAPSHOTS, any()) } coAnswers {
                if (!marked) {
                    marked = true
                    w.repo.markForDelete(1L) // the user deletes scan 1 after the walk read it
                }
                callOriginal()
            }

            assertTrue(spy.run(NOW).completed)
            assertEquals("DELETING", w.f.db.openHelper.readableDatabase
                .query("SELECT state FROM ScanResult WHERE id = 1").use { c -> c.moveToFirst(); c.getString(0) })
            assertEquals("the batch leaves a DELETING scan to its delete", 601L, observations(1L))
            assertNoUnpinnedOrphan()

            w.repo.completeDelete(1L)

            assertEquals(0L, w.count("SELECT COUNT(*) FROM ScanResult WHERE id = 1"))
            assertEquals(0L, observations(1L))
            assertNoUnpinnedOrphan()
            assertEquals("scan 2 is untouched", 1L, observations(2L))
        }

    /**
     * D4 fix: retention leaves a finding's fact pinned only by that finding; deleting the scan later
     * removes the pin and must release the fact in the same pass (A5), not leave it for a GC.
     */
    @Test
    fun `deleting a scan that retention trimmed releases the facts its findings pinned`() = runBlocking {
        liveScan(1L, listOf(app(EVIL_APP), app("com.s1")))
        liveScan(2L, listOf(app("com.s2")))
        settings.setSnapshotRetentionScans(1)
        retention.run(NOW)
        assertEquals(0L, observations(1L))
        assertEquals("the finding pins EVIL_APP's fact", 1L,
            w.count("SELECT COUNT(*) FROM telemetry_record WHERE packageName = '$EVIL_APP'"))

        w.repo.markForDelete(1L)
        w.repo.completeDelete(1L)

        assertEquals(0L, w.count("SELECT COUNT(*) FROM telemetry_record WHERE packageName = '$EVIL_APP'"))
        assertNoUnpinnedOrphan()
    }

    /** Review m4: a newer scan deleted mid-cycle never makes a scan within the newest N lose its snapshots. */
    @Test
    fun `a newer scan deleted mid-cycle does not trim a scan that is now within the newest N`() = runBlocking {
        for (id in 1L..4L) liveScan(id, listOf(app("com.s$id")))
        settings.setSnapshotRetentionScans(2)
        val spy = spyk(retention)
        var deleted = false
        coEvery { spy.batch(3L, TelemetryRetention.Phase.EVENTS, any()) } coAnswers {
            if (!deleted) {
                deleted = true
                w.repo.markForDelete(4L) // the newest scan goes after the walk ranked it
                w.repo.completeDelete(4L)
            }
            callOriginal()
        }

        assertTrue(spy.run(NOW).completed)

        assertEquals("scan 2 is now among the newest 2 and keeps its snapshots", 1L, observations(2L))
        assertEquals(TelemetryState.STORED.name, state(2L))
        assertEquals("scan 1 is beyond them", 0L, observations(1L))
    }
}
