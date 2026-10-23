package com.androdr.ui.timeline

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.androdr.data.db.TimelineFilter
import com.androdr.data.db.TimelineKey
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.scanner.WriterFixture
import com.androdr.sigma.StoreRecord
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * T1 (spec §6, §9): a 100,000-event import with 50 writer-produced finding rows pages fully through
 * the Timeline's keyset union — counts match, nothing is duplicated, each finding's evidence is
 * nested under it, no SQL uses OFFSET, scroll position survives an invalidation, an uncommitted
 * import (facts and finding rows) is invisible, and the severity filter returns exactly the
 * writer-produced rows of that level.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineUncappedTest {
    private val w = WriterFixture()
    private val entries = TimelineEntries(w.f.db, w.f.reader)

    @After fun tearDown() = w.close()

    /** Four lines per millisecond (time ties); every 2,000th line a hit: 20 high, 30 medium. */
    private fun line(i: Int, scanTag: Int = 0): StoreRecord {
        val time = BASE + i / 4
        val tag = when {
            i % 2_000 != 7 -> "other"
            (i / 2_000) % 5 < 2 -> HIGH_TAG
            else -> "adb_shell_cmd"
        }
        val fields = WriterFixture.securityLine(time = time, tag = tag).fields
        return StoreRecord(fields, "210001 $scanTag-$i $time")
    }

    private fun source(filter: TimelineFilter = TimelineFilter()) = TimelinePagingSource(w.f.db, filter, entries)

    private suspend fun TimelinePagingSource.page(params: PagingSource.LoadParams<TimelineKey>) =
        load(params) as PagingSource.LoadResult.Page<TimelineKey, TimelineRow.Entry>

    private suspend fun everything(filter: TimelineFilter): List<TimelineRow.Entry> {
        val s = source(filter)
        val out = ArrayList<TimelineRow.Entry>()
        var page = s.page(PagingSource.LoadParams.Refresh(null, PAGE, false))
        out += page.data
        while (page.nextKey != null) {
            page = s.page(PagingSource.LoadParams.Append(page.nextKey!!, PAGE, false))
            out += page.data
        }
        return out
    }

    private fun awaitInvalid(s: PagingSource<*, *>): Boolean {
        repeat(200) {
            w.f.db.invalidationTracker.refreshVersionsSync()
            if (s.invalid) return true
            Thread.sleep(10)
        }
        return false
    }

    private fun ids(sql: String): Set<Long> = w.f.db.openHelper.readableDatabase.query(sql)
        .use { c -> buildSet { while (c.moveToNext()) add(c.getLong(0)) } }

    @Test
    fun `100,000 event facts and 50 finding rows page fully, uncapped`() = runBlocking {
        writeImports()

        val findingRowIds = ids("SELECT id FROM forensic_timeline WHERE scanResultId = $SCAN AND ruleId != ''")
        assertEquals("the writer produced 50 finding rows", 50, findingRowIds.size)
        val visibleFacts = ids("SELECT recordId FROM scan_record WHERE scanId = $SCAN")
        assertEquals(EVENTS, visibleFacts.size)
        val pendingFacts = ids("SELECT recordId FROM scan_record WHERE scanId = $PENDING") - visibleFacts

        val all = everything(TimelineFilter())

        // Counts: every event and every finding row (nested evidence is shown, so it counts).
        assertEquals(100_050L, entries.count(TimelineFilter()))
        val stored = all.filterIsInstance<TimelineRow.StoredRow>()
        val events = all.filterIsInstance<TimelineRow.EventRow>()
        assertEquals(findingRowIds, stored.map { it.entity.id }.toSet())
        assertEquals(EVENTS - 50, events.size)
        // No duplicates, display order.
        assertEquals(all.size, all.map { "${it.entity.rowKind}:${it.entity.id}" }.toSet().size)
        assertEquals(all.map { it.key }.sortedWith(TimelineKey.DISPLAY_ORDER), all.map { it.key })
        // Evidence is nested: each finding row carries its fact, which is not listed on its own.
        val evidence = stored.map { assertNotNull(it.evidence); it.evidence!!.factId }
        assertEquals(stored.map { it.event.recordId }, evidence)
        assertTrue(events.none { it.record.factId in evidence.toSet() })
        assertEquals("every fact reachable exactly once", visibleFacts,
            (events.map { it.record.factId } + evidence).toSet())
        // The uncommitted import is invisible.
        assertTrue(all.none { it.entity.scanId == PENDING })
        assertTrue(all.none { it is TimelineRow.EventRow && it.entity.id in pendingFacts })
        // Severity: exactly the writer-produced HIGH rows.
        val highIds = ids("SELECT id FROM forensic_timeline WHERE scanResultId = $SCAN AND level = 'high'")
        assertEquals(20, highIds.size)
        val high = everything(TimelineFilter(levels = setOf("HIGH")))
        assertEquals(highIds, high.map { it.entity.id }.toSet())
        assertTrue(high.all { it is TimelineRow.StoredRow && it.event.ruleId == HIGH_RULE })
        assertEquals("the 20 rows and their nested evidence (what the list shows)", 40L,
            entries.count(TimelineFilter(levels = setOf("HIGH"))))
        // No OFFSET in anything the Timeline ran.
        val sql = synchronized(w.f.sql) { w.f.sql.toList() }
        assertTrue(sql.any { "forensic_timeline r" in it })
        val offsets = sql.filter { "OFFSET" in it.uppercase() }
        assertTrue(offsets.joinToString("\n"), offsets.isEmpty())

        // Scroll position survives an invalidation (a new Timeline row).
        assertScrollSurvivesInvalidation(all)
    }

    /** The 100,000-line import (finished), and an uncommitted import with a finding row of its scan. */
    private suspend fun writeImports() {
        w.f.recording = false
        w.engine.setRemoteRules(listOf(
            WriterFixture.rule(WriterFixture.SEC_RULE, "security_log", "tag_name", "adb_shell_cmd", "medium"),
            WriterFixture.rule(HIGH_RULE, "security_log", "tag_name", HIGH_TAG, "high"),
        ))
        val imp = w.scan(SCAN, TelemetrySource.INTRUSION_LOG_IMPORT)
        w.writer.begin(imp, liveEvents = false).apply {
            appendAll("security_log", TelemetrySource.INTRUSION_LOG_IMPORT, WriterFixture.IMPORT_CAPTURED,
                (0 until EVENTS).asSequence().map { line(it) })
            finish()
        }
        // An uncommitted import: its facts, and a finding row of its scan, must not show.
        val pending = w.writer.begin(w.scan(PENDING, TelemetrySource.INTRUSION_LOG_IMPORT), liveEvents = false)
        pending.appendAll("security_log", TelemetrySource.INTRUSION_LOG_IMPORT, WriterFixture.IMPORT_CAPTURED,
            (0 until 100).asSequence().map { line(it * 1_000 + 7, scanTag = 2) })
        w.f.db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = PENDING, source = "app_scanner",
            category = "app_risk", description = "pending", ruleId = HIGH_RULE, level = "high", scanResultId = PENDING))
        w.f.recording = true
    }

    private suspend fun assertScrollSurvivesInvalidation(all: List<TimelineRow.Entry>) {
        val old = source()
        val p1 = old.page(PagingSource.LoadParams.Refresh(null, PAGE, false))
        val p2 = old.page(PagingSource.LoadParams.Append(p1.nextKey!!, PAGE, false))
        w.f.db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = 1L, source = "audit",
            category = "audit", description = "later", persistent = true))
        assertTrue(awaitInvalid(old))
        val anchor = PAGE + PAGE / 2
        val state = PagingState(listOf(p1, p2), anchorPosition = anchor,
            config = PagingConfig(pageSize = PAGE, initialLoadSize = PAGE), leadingPlaceholderCount = 0)
        val reloaded = source().page(PagingSource.LoadParams.Refresh(old.getRefreshKey(state), PAGE, false))
        assertTrue("the anchored entry is on the reloaded page", reloaded.data.any { it.key == p2.data[PAGE / 2].key })
        val back = source().page(PagingSource.LoadParams.Prepend(reloaded.prevKey!!, PAGE, false))
        val at = all.indexOfFirst { it.key == reloaded.data.first().key }
        assertEquals("prepend continues the list just above the reloaded page",
            all.subList(at - back.data.size, at).map { it.key }, back.data.map { it.key })
    }

    private companion object {
        const val EVENTS = 100_000
        const val PAGE = 500
        const val BASE = 1_729_000_000_000L
        const val SCAN = 1_800_000_000_000L
        const val PENDING = 1_800_000_000_001L
        const val HIGH_RULE = "androdr-t-sec-high"
        const val HIGH_TAG = "hit_high"
    }
}
