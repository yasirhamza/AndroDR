package com.androdr.ui.timeline

import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.SignalMember
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.scanner.WriterFixture
import com.androdr.sigma.StoreRecord
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * C4 review I2: what the Timeline union shows, by spec §3 and §5.1.
 * - Snapshot records never appear (a snapshot record carries no event time, even when its fields
 *   hold a timestamp-like value), and day-precision event facts are left out.
 * - A DELETING scan's facts and rows are invisible, like an IN_PROGRESS one's.
 * - A pinned orphan (no observation left) shows: standalone when a `signal_member` pins it, nested
 *   under a persistent row that points at it; an unpinned orphan never shows.
 * Counts agree with what pages.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineVisibilityTest {
    private val f = StoreFixture(recordSql = false)
    private val entries = TimelineEntries(f.db, f.reader)

    @After fun tearDown() = f.close()

    private fun line(i: Int, t: Long) = StoreRecord(WriterFixture.securityLine(time = t).fields, "210001 v$i $t")

    private fun battery(t: Long, precision: String) = StoreRecord(mapOf("package_name" to "com.b", "event" to "install",
        "timestamp" to t, "timestamp_precision" to precision, "source" to "BUGREPORT_IMPORT"))

    private suspend fun all(): List<TimelineRow.Entry> {
        val out = ArrayList<TimelineRow.Entry>()
        entries.forEachPage(TimelineFilter(), oldestFirst = false, size = 3) { out += it }
        return out
    }

    private fun exec(sql: String) = f.db.openHelper.writableDatabase.execSQL(sql)

    @Test
    fun `only visible event facts and rows appear, and pinned orphans as the pin rule says`() = runBlocking {
        f.scan(1L)
        val events = f.persist(1L, "security_log", listOf(line(1, BASE + 1), line(2, BASE + 2)),
            source = TelemetrySource.INTRUSION_LOG_IMPORT).factIdByChunkIndex.toList()
        val snapshot = StoreRecord(app("com.snap").fields + ("timestamp" to BASE + 3))
        val snapshots = f.persist(1L, "app_scanner", listOf(app("com.a"), snapshot)).factIdByChunkIndex.toList()
        val day = f.persist(1L, "battery_daily", listOf(battery(BASE + 4, "day")),
            source = TelemetrySource.BUGREPORT_IMPORT).factIdByChunkIndex.single()
        f.setState(1L, ScanState.COMPLETE)
        // A DELETING scan: its fact and its row are hidden.
        f.scan(2L)
        val deleting = f.persist(2L, "security_log", listOf(line(3, BASE + 5)),
            source = TelemetrySource.INTRUSION_LOG_IMPORT).factIdByChunkIndex.single()
        f.setState(2L, ScanState.DELETING)
        val dao = f.db.forensicTimelineEventDao()
        dao.insert(ForensicTimelineEvent(startTimestamp = BASE + 6, source = "app_scanner", category = "app_risk",
            description = "deleting", ruleId = "r", scanResultId = 2L))
        // Orphans: observed by scan 3, then their observations removed (deletion or retention).
        f.scan(3L)
        val orphans = f.persist(3L, "security_log", (7..9).map { line(it, BASE + it) },
            source = TelemetrySource.INTRUSION_LOG_IMPORT).factIdByChunkIndex.toList()
        f.setState(3L, ScanState.COMPLETE)
        exec("DELETE FROM scan_record WHERE scanId = 3")
        f.db.signalMemberDao().insertAll(listOf(SignalMember(99L, SignalMember.KIND_FACT, orphans[0])))
        val audit = dao.insert(ForensicTimelineEvent(startTimestamp = BASE + 10, source = "audit", category = "audit",
            description = "audit", persistent = true, recordId = orphans[1]))
        // orphans[2] is pinned by nothing: never visible.

        assertTrue("a snapshot record has no event time, whatever its fields hold", f.count(
            "SELECT COUNT(*) FROM telemetry_record WHERE service = 'app_scanner' AND eventTime IS NOT NULL") == 0L)
        assertEquals("the battery fact is a day-precision event fact", 1L, f.count("SELECT COUNT(*) FROM " +
            "telemetry_record WHERE id = $day AND timePrecision = 'DAY' AND eventTime IS NOT NULL"))
        val got = all()
        val facts = got.filterIsInstance<TimelineRow.EventRow>().map { it.record.factId }.toSet()
        val rows = got.filterIsInstance<TimelineRow.StoredRow>()

        assertEquals(setOf(events[0], events[1], orphans[0]), facts)
        assertTrue(facts.none { it in snapshots || it == day || it == deleting || it == orphans[2] })
        assertEquals("the DELETING scan's row is hidden; the persistent row shows", listOf(audit),
            rows.map { it.event.id })
        assertEquals("the orphan pinned by the persistent row is nested under it", orphans[1],
            rows.single().evidence?.factId)
        assertEquals("count = 2 events + the signal-pinned orphan + the row + its evidence", 5L,
            entries.count(TimelineFilter()))
    }

    private companion object {
        const val BASE = 1_729_000_000_000L
    }
}
