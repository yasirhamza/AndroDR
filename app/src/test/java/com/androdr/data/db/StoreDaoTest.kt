package com.androdr.data.db

import android.content.Context
import androidx.room.Room
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.test.core.app.ApplicationProvider
import com.androdr.data.model.EventWatermark
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.RecordBody
import com.androdr.data.model.ScanObservation
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.SignalMember
import com.androdr.data.model.TelemetryFact
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.data.store.HashKeys.h128
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.Collections
import java.util.concurrent.Executor

/** Schema-20 store DAOs: identity, observations, pins, J1 join, keyset plans (spec §5.1, §5.4). */
@RunWith(RobolectricTestRunner::class)
class StoreDaoTest {
    private val captured: MutableList<Pair<String, List<Any?>>> = Collections.synchronizedList(mutableListOf())
    private lateinit var db: AppDatabase

    @Before fun setUp() {
        db = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext<Context>(), AppDatabase::class.java)
            .allowMainThreadQueries()
            .setQueryCallback({ sql, args -> captured += sql to args.toList() }, Executor { it.run() })
            .build()
    }

    @After fun tearDown() { db.close() }

    private val facts get() = db.telemetryFactDao()
    private val obs get() = db.scanObservationDao()
    private val bodies get() = db.recordBodyDao()

    private fun body(tag: String) = RecordBody(h128("body:$tag"), encoding = 0, dictVersion = 0,
        body = tag.toByteArray(), rawBytes = tag.length)

    private fun fact(tag: String, service: String = "dns_monitor", sourceKey: ByteArray? = null) = TelemetryFact(
        service = service, factKey = h128("fact:$tag"), sourceKey = sourceKey, subjectKey = "s:$tag",
        eventTime = 1_000L, timePrecision = "EXACT", category = "dns_query", packageName = "com.example",
        bodyHash = h128("body:$tag")
    )

    private fun observation(scanId: Long, ordinal: Int, recordId: Long, service: String = "dns_monitor") =
        ScanObservation(scanId = scanId, service = service, ordinal = ordinal, recordId = recordId, eventTime = 1_000L,
            source = TelemetrySource.LIVE_SCAN, capturedAt = 5L, strippedKeys = 0)

    private fun scan(id: Long) = ScanResult(id = id, timestamp = id, findings = emptyList(),
        bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0)

    private fun plan(sql: String, args: List<Any?>): List<String> =
        db.openHelper.writableDatabase.query(SimpleSQLiteQuery("EXPLAIN QUERY PLAN $sql", args.toTypedArray()))
            .use { c -> buildList { while (c.moveToNext()) add(c.getString(c.getColumnIndexOrThrow("detail"))) } }

    private fun capturedLike(fragment: String): Pair<String, List<Any?>> =
        captured.last { it.first.contains(fragment) }

    @Test
    fun `J1 - a live DNS fact and its ioc_match row join on sourceKey = sourceEventKey`() = runBlocking {
        bodies.insertIgnore(listOf(body("dns7")))
        val id = facts.insertIgnore(listOf(fact("dns7", sourceKey = h128("dns:7")))).single()
        db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = 1L, source = "dns_monitor",
            category = "ioc_match", description = "d", sourceEventKey = h128("dns:7")))
        val row = db.forensicTimelineEventDao().getAllForExport().single()
        val joined = facts.idsBySourceKey(listOf(row.sourceEventKey!!))
        assertEquals(listOf(id), joined.map { it.id })
        assertArrayEquals(h128("dns:7"), joined.single().key)
        db.openHelper.readableDatabase.query(
            "SELECT t.id FROM telemetry_record t JOIN forensic_timeline f ON f.sourceEventKey = t.sourceKey " +
                "WHERE f.category = 'ioc_match'"
        ).use { c -> c.moveToFirst(); assertEquals(id, c.getLong(0)) }
    }

    @Test
    fun `a duplicate fact returns -1 and idsFor finds the original`() = runBlocking {
        val first = facts.insertIgnore(listOf(fact("a"))).single()
        val again = facts.insertIgnore(listOf(fact("a"), fact("b")))
        assertEquals(-1L, again[0])
        assertTrue(again[1] > first)
        val found = facts.idsFor("dns_monitor", listOf(h128("fact:a"), h128("fact:missing")))
        assertEquals(listOf(first), found.map { it.id })
        assertArrayEquals(h128("fact:a"), found.single().key)
        assertTrue(facts.idsFor("network_monitor", listOf(h128("fact:a"))).isEmpty())
    }

    @Test
    fun `unique scanId recordId drops a duplicate observation`() = runBlocking {
        val id = facts.insertIgnore(listOf(fact("a"))).single()
        val r = obs.insertIgnore(listOf(observation(1L, 0, id), observation(1L, 1, id), observation(2L, 0, id)))
        assertTrue(r[0] > 0)
        assertEquals(-1L, r[1])
        assertTrue(r[2] > 0)
        assertEquals(listOf(ObservationKey("dns_monitor", 0, id)), obs.factIdsAfter(1L, "", -1, 10))
        assertEquals(listOf(OrdinalFact(0, id)), obs.factIdsForOrdinals(1L, "dns_monitor", listOf(0, 1)))
    }

    @Test
    fun `factIdsAfter pages by keyset on the observation PK`() = runBlocking {
        val ids = facts.insertIgnore((0 until 5).map { fact("f$it", service = if (it < 3) "a_svc" else "b_svc") })
        obs.insertIgnore(ids.mapIndexed { i, id ->
            observation(9L, if (i < 3) i else i - 3, id, if (i < 3) "a_svc" else "b_svc")
        })
        val p1 = obs.factIdsAfter(9L, "", -1, 2)
        val p2 = obs.factIdsAfter(9L, p1.last().service, p1.last().ordinal, 2)
        val p3 = obs.factIdsAfter(9L, p2.last().service, p2.last().ordinal, 2)
        assertEquals(ids, (p1 + p2 + p3).map { it.recordId })
        assertEquals(listOf("a_svc" to 2, "b_svc" to 0), p2.map { it.service to it.ordinal })
        val (sql, args) = capturedLike("FROM scan_record WHERE scanId")
        val detail = plan(sql, args).joinToString("\n")
        assertTrue(detail, detail.contains("sqlite_autoindex_scan_record_1"))
        assertTrue(detail, !detail.contains("TEMP B-TREE"))
    }

    @Test
    fun `deleteUnobservedUnpinned keeps observed, signal-pinned and timeline-pinned facts`() = runBlocking {
        val ids = facts.insertIgnore(listOf(fact("observed"), fact("signal"), fact("timeline"), fact("orphan")))
        obs.insertIgnore(listOf(observation(1L, 0, ids[0])))
        db.signalMemberDao().insertAll(listOf(
            SignalMember(signalRowId = 77L, kind = SignalMember.KIND_FACT, refId = ids[1]),
            SignalMember(signalRowId = 77L, kind = SignalMember.KIND_ROW, refId = ids[3]),
        ))
        db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = 1L, source = "app_scanner",
            category = "app_risk", description = "d", recordId = ids[2]))
        facts.deleteUnobservedUnpinned(ids)
        assertTrue(facts.unobservedUnpinnedAfter(0L, 10).isEmpty())
        val keys = listOf("observed", "signal", "timeline", "orphan").map { h128("fact:$it") }
        val left = facts.idsFor("dns_monitor", keys)
        assertEquals(ids.take(3), left.map { it.id }.sorted())
    }

    @Test
    fun `unobservedUnpinnedAfter lists only unobserved unpinned facts by keyset`() = runBlocking {
        val ids = facts.insertIgnore((0 until 5).map { fact("u$it") })
        obs.insertIgnore(listOf(observation(1L, 0, ids[1])))
        db.signalMemberDao().insertAll(listOf(SignalMember(1L, SignalMember.KIND_FACT, ids[3])))
        assertEquals(listOf(ids[0], ids[2]), facts.unobservedUnpinnedAfter(0L, 2))
        assertEquals(listOf(ids[4]), facts.unobservedUnpinnedAfter(ids[2], 2))
    }

    @Test
    fun `bodies are deleted only when no fact references them`() = runBlocking {
        bodies.insertIgnore(listOf(body("kept"), body("gone"), body("kept")))
        facts.insertIgnore(listOf(fact("kept")))
        assertEquals(listOf(h128("body:kept").toList()), facts.bodyHashesOf(facts.idsFor("dns_monitor",
            listOf(h128("fact:kept"))).map { it.id }).map { it.toList() })
        bodies.deleteUnreferenced(listOf(h128("body:kept"), h128("body:gone")))
        db.openHelper.readableDatabase.query("SELECT hash FROM record_body").use { c ->
            assertEquals(1, c.count)
            c.moveToFirst()
            assertArrayEquals(h128("body:kept"), c.getBlob(0))
        }
    }

    @Test
    fun `liveObserved returns facts with a live observation in a COMPLETE scan only`() = runBlocking {
        db.scanResultDao().insert(scan(1L))
        db.scanResultDao().insertInProgress(scan(2L))
        val ids = facts.insertIgnore(listOf(fact("x"), fact("y"), fact("z")))
        obs.insertIgnore(listOf(observation(1L, 0, ids[0]), observation(2L, 0, ids[1]),
            observation(1L, 1, ids[2]).copy(source = TelemetrySource.BUGREPORT_IMPORT)))
        assertEquals(listOf(ids[0]), facts.liveObserved(ids))
    }

    @Test
    fun `signal members insert or ignore, page by kind and refId, and delete per signal`() = runBlocking {
        val dao = db.signalMemberDao()
        dao.insertAll(listOf(SignalMember(5L, 1, 20L), SignalMember(5L, 0, 30L), SignalMember(5L, 1, 10L),
            SignalMember(5L, 1, 10L), SignalMember(6L, 0, 1L)))
        val p1 = dao.forSignal(5L, null, null, 2)
        assertEquals(listOf(0 to 30L, 1 to 10L), p1.map { it.kind to it.refId })
        val p2 = dao.forSignal(5L, p1.last().kind, p1.last().refId, 2)
        assertEquals(listOf(1 to 20L), p2.map { it.kind to it.refId })
        dao.deleteForSignals(listOf(5L))
        assertTrue(dao.forSignal(5L, null, null, 10).isEmpty())
        assertEquals(1, dao.forSignal(6L, null, null, 10).size)
    }

    @Test
    fun `watermarks put replaces and get reads back`() = runBlocking {
        val dao = db.eventWatermarkDao()
        assertNull(dao.get("dns_monitor"))
        dao.put(EventWatermark("dns_monitor", position = 10L, scanId = 1L))
        dao.put(EventWatermark("dns_monitor", position = 25L, scanId = 2L))
        assertEquals(EventWatermark("dns_monitor", 25L, 2L), dao.get("dns_monitor"))
    }

    @Test
    fun `scan state - in-progress and deleting scans are hidden from lists and sweepable`() = runBlocking {
        val dao = db.scanResultDao()
        dao.insert(scan(1L))
        dao.insertInProgress(scan(2L))
        dao.insertInProgress(scan(3L))
        assertEquals(listOf(1L), dao.getAllScans().first().map { it.id })
        assertEquals(listOf(1L), dao.getLatestTwo().map { it.id })
        assertEquals(setOf(2L, 3L), dao.sweepableIds().toSet())
        assertEquals(1, dao.complete(2L, TelemetryState.STORED))
        assertEquals(0, dao.complete(2L, TelemetryState.STORED))
        assertEquals(0, dao.complete(1L, TelemetryState.STORED))
        val latest = dao.getLatestTwo()
        assertEquals(listOf(2L, 1L), latest.map { it.id }.sortedDescending())
        assertEquals(ScanState.COMPLETE, latest.single { it.id == 2L }.state)
        assertEquals(TelemetryState.STORED, latest.single { it.id == 2L }.telemetryState)
        assertEquals(TelemetryState.NONE, latest.single { it.id == 1L }.telemetryState)
        assertEquals(listOf(3L), dao.sweepableIds())
    }

    @Test
    fun `no store query uses OFFSET and every delete is index-driven`() = runBlocking {
        db.scanResultDao().insert(scan(1L))
        bodies.insertIgnore(listOf(body("a")))
        val ids = facts.insertIgnore(listOf(fact("a", sourceKey = h128("dns:1"))))
        obs.insertIgnore(listOf(observation(1L, 0, ids[0])))
        facts.idsFor("dns_monitor", listOf(h128("fact:a")))
        facts.liveObserved(ids)
        facts.unobservedUnpinnedAfter(0L, 10)
        facts.bodyHashesOf(ids)
        facts.idsBySourceKey(listOf(h128("dns:1")))
        obs.factIdsAfter(1L, "", -1, 10)
        obs.factIdsForOrdinals(1L, "dns_monitor", listOf(0))
        db.eventWatermarkDao().get("dns_monitor")
        db.signalMemberDao().forSignal(1L, null, null, 10)
        db.scanResultDao().sweepableIds()
        db.signalMemberDao().deleteForSignals(listOf(1L))
        facts.deleteUnobservedUnpinned(ids)
        bodies.deleteUnreferenced(listOf(h128("body:a")))
        obs.deleteThrough(1L, "dns_monitor", 0)
        obs.deleteForScan(1L)
        val sqls = captured.toList()
        assertTrue(sqls.none { it.first.uppercase().contains("OFFSET") })
        val deletes = sqls.filter { it.first.trimStart().uppercase().startsWith("DELETE") }
        assertEquals(5, deletes.map { it.first }.distinct().size)
        for ((sql, args) in deletes) {
            val lines = plan(sql, args)
            val scans = lines.filter { Regex("^SCAN\\b").containsMatchIn(it.trim()) }
            assertTrue("full scan in $sql:\n${lines.joinToString("\n")}", scans.isEmpty())
        }
    }

    @Test
    fun `fresh schema keeps fact and timeline ids AUTOINCREMENT`() {
        for (t in listOf("telemetry_record", "forensic_timeline")) {
            db.openHelper.readableDatabase.query("SELECT sql FROM sqlite_master WHERE name = '$t'").use { c ->
                c.moveToFirst()
                assertTrue(c.getString(0), c.getString(0).contains("`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL"))
            }
        }
    }

    @Test
    fun `onOpen callback sets the journal size limit`() {
        val cbDb = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext<Context>(),
            AppDatabase::class.java).addCallback(JournalSizeLimitCallback).allowMainThreadQueries().build()
        try {
            cbDb.openHelper.readableDatabase.query("PRAGMA journal_size_limit").use { c ->
                c.moveToFirst()
                assertEquals(JournalSizeLimitCallback.LIMIT_BYTES, c.getLong(0))
            }
        } finally {
            cbDb.close()
        }
    }
}
