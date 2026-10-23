package com.androdr.data.store

import androidx.paging.PagingSource
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.StoreFixture.Companion.dns
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** [TelemetryReader]: COMPLETE-only visibility, pinned orphans, cross-scan reads (spec §5.1). */
@RunWith(RobolectricTestRunner::class)
class TelemetryReaderTest {
    private val f = StoreFixture()

    @After fun tearDown() = f.close()

    private suspend fun names(scanId: Long, service: String = "app_scanner"): List<Any?> {
        val out = mutableListOf<Any?>()
        f.reader.forEach(scanId, service) { out += it.fields?.get("package_name") ?: it.fields?.get("domain") }
        return out
    }

    private suspend fun firstPage(scanId: Long, service: String): List<DecodedRecord> {
        val result = f.reader.pagingSource(scanId, service)
            .load(PagingSource.LoadParams.Refresh(null, 50, false))
        return (result as PagingSource.LoadResult.Page).data
    }

    @Test
    fun `records of IN_PROGRESS and DELETING scans are invisible to every reader method`() = runBlocking {
        for ((id, state) in listOf(1L to ScanState.IN_PROGRESS, 2L to ScanState.DELETING)) {
            f.scan(id)
            f.persist(id, "app_scanner", listOf(app("com.a"), app("com.b")), live = true)
            f.persist(id, "dns_monitor", listOf(dns("x.example")), live = true)
            f.setState(id, state)
        }
        val ids = (1L..10L).toList()
        for (id in 1L..2L) {
            assertTrue(f.reader.services(id).isEmpty())
            assertTrue(names(id).isEmpty())
            assertTrue(firstPage(id, "app_scanner").isEmpty())
        }
        assertTrue(f.reader.history("app_scanner", "com.a").first().isEmpty())
        assertTrue(f.reader.changedBetween(1L, 2L, "app_scanner").isEmpty())
        assertNull(f.reader.latestLive("app_scanner", Long.MAX_VALUE / 2))
        assertTrue(f.reader.records(ids).isEmpty())
        assertEquals(StorageSummary.EMPTY, f.reader.storage())
    }

    @Test
    fun `a pinned fact with no remaining observation is readable through records and history`() = runBlocking {
        f.scan(1L)
        val r = f.persist(1L, "app_scanner", listOf(app("com.pinned"), app("com.loose")))
        f.setState(1L, ScanState.COMPLETE)
        f.pinByTimeline(r.factIdByChunkIndex[0])
        f.setState(1L, ScanState.DELETING)
        f.store.deleteScanTelemetry(1L)
        val read = f.reader.records(r.factIdByChunkIndex.toList())
        assertEquals(listOf(r.factIdByChunkIndex[0]), read.map { it.factId })
        assertEquals(-1L, read.single().scanId)
        assertEquals("com.pinned", read.single().fields!!["package_name"])
        val history = f.reader.history("app_scanner", "com.pinned").first()
        assertEquals(listOf(r.factIdByChunkIndex[0]), history.map { it.factId })
        assertTrue(f.reader.history("app_scanner", "com.loose").first().isEmpty())
        assertEquals(1L, f.reader.storage().pinnedOrphans.bodies)
    }

    @Test
    fun `history lists a subject across COMPLETE scans in capture order`() = runBlocking {
        for ((scan, version) in listOf(1L to 1L, 2L to 2L, 3L to 3L)) {
            f.scan(scan)
            f.persist(scan, "app_scanner", listOf(app("com.h", version)), capturedAt = scan * 1000)
            if (scan != 3L) f.setState(scan, ScanState.COMPLETE)
        }
        val h = f.reader.history("app_scanner", "com.h").first()
        assertEquals(listOf(1L, 2L), h.map { it.scanId })
        assertEquals(listOf(1L, 2L), h.map { it.fields!!["version_code"] })
    }

    @Test
    fun `changedBetween pairs changed subjects and lists added and removed ones`() = runBlocking {
        f.scan(1L)
        f.persist(1L, "app_scanner", listOf(app("a", 1), app("b"), app("c")))
        f.scan(2L)
        f.persist(2L, "app_scanner", listOf(app("a", 2), app("b"), app("d")))
        f.setState(1L, ScanState.COMPLETE)
        f.setState(2L, ScanState.COMPLETE)
        val changes = f.reader.changedBetween(1L, 2L, "app_scanner")
        assertEquals(listOf("a", "c", "d"), changes.map { it.subjectKey })
        val a = changes.first()
        assertEquals(1L, a.before!!.fields!!["version_code"])
        assertEquals(2L, a.after!!.fields!!["version_code"])
        assertNull(changes[1].after)
        assertNull(changes[2].before)
    }

    @Test
    fun `latestLive returns the newest fresh live scan's records or null`() = runBlocking {
        val now = System.currentTimeMillis()
        f.scan(1L)
        f.persist(1L, "app_scanner", listOf(app("old")), capturedAt = now - 600_000L, live = true)
        f.setState(1L, ScanState.COMPLETE)
        assertNull(f.reader.latestLive("app_scanner", TelemetryReader.APP_ENRICHMENT_MAX_AGE_MS))
        f.scan(2L)
        f.persist(2L, "app_scanner", listOf(app("new1"), app("new2")), capturedAt = now, live = true)
        f.setState(2L, ScanState.COMPLETE)
        f.scan(3L) // a newer import does not count
        f.persist(3L, "app_scanner", listOf(app("imp")), source = TelemetrySource.BUGREPORT_IMPORT,
            capturedAt = now + 1)
        f.setState(3L, ScanState.COMPLETE)
        val live = f.reader.latestLive("app_scanner", TelemetryReader.APP_ENRICHMENT_MAX_AGE_MS)
        assertEquals(listOf("new1", "new2"), live!!.map { it.fields!!["package_name"] })
    }

    @Test
    fun `records omits missing ids and batches beyond the bound-variable limit`() = runBlocking {
        f.scan(1L)
        val r = f.persist(1L, "app_scanner", listOf(app("x"), app("y")))
        f.setState(1L, ScanState.COMPLETE)
        val ids = (1L..2_000L).toList() + r.factIdByChunkIndex.toList()
        assertEquals(r.factIdByChunkIndex.toSet(), f.reader.records(ids).map { it.factId }.toSet())
    }

    @Test
    fun `reader queries other than the storage totals never full-scan a store table`() = runBlocking {
        f.scan(1L)
        val r = f.persist(1L, "app_scanner", listOf(app("x"), app("y")), live = true)
        f.setState(1L, ScanState.COMPLETE)
        f.sql.clear()
        f.reader.services(1L)
        names(1L)
        firstPage(1L, "app_scanner")
        f.reader.history("app_scanner", "x").first()
        f.reader.changedBetween(1L, 1L, "app_scanner")
        f.reader.latestLive("app_scanner", 60_000L)
        f.reader.records(r.factIdByChunkIndex.toList())
        val reads = f.sql.toList().distinct().filter { it.trimStart().startsWith("SELECT") && "scan_record" in it }
        assertEquals(6, reads.size) // services, pageAfter, history, onlyIn, latestLiveScan, records
        val db = f.db.openHelper.readableDatabase
        for (q in reads) {
            val args = arrayOfNulls<Any>(q.count { it == '?' }).also { it.fill(1L) }
            val plan = db.query(androidx.sqlite.db.SimpleSQLiteQuery("EXPLAIN QUERY PLAN $q", args))
                .use { c -> buildList { while (c.moveToNext()) add(c.getString(c.getColumnIndexOrThrow("detail"))) } }
            val full = plan.filter { it.trim().startsWith("SCAN") && !it.contains("USING") }
            assertTrue("full scan in $q:\n${plan.joinToString("\n")}", full.isEmpty())
        }
    }

    @Test
    fun `services, summaries and storage reflect COMPLETE scans`() = runBlocking {
        f.scan(1L)
        f.persist(1L, "app_scanner", listOf(app("x"), app("y")))
        f.persist(1L, "dns_monitor", listOf(dns("a.example"), dns("b.example"), dns("c.example")))
        f.setState(1L, ScanState.COMPLETE)
        assertEquals(listOf("app_scanner" to 2, "dns_monitor" to 3),
            f.reader.services(1L).map { it.service to it.records })
        val events = firstPage(1L, "dns_monitor")
        assertTrue(events.all { it.summary != null && it.summary!!.contains(".example") })
        assertTrue(firstPage(1L, "app_scanner").all { it.summary == null })
        val s = f.reader.storage()
        assertEquals(2L, s.snapshots.bodies)
        assertEquals(3L, s.events.bodies)
        assertEquals(0L, s.pinnedOrphans.bodies)
        assertTrue(s.events.storedBytes > 0 && s.events.rawBytes > 0)
    }
}
