package com.androdr.ui.timeline

import androidx.paging.PagingSource
import com.androdr.data.db.TimelineFilter
import com.androdr.data.db.TimelineKey
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TimelineRowEntity
import com.androdr.data.store.StoreFixture
import com.androdr.scanner.WriterFixture
import com.androdr.sigma.StoreRecord
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * C4 review I1: rows and facts sharing one timestamp, split across page boundaries. For every small
 * page size, an append walk from the top, and from a refresh at every key a full prepend walk back
 * to the top plus an append walk to the end, give exactly the expected list (no skip, no
 * duplicate), computed independently by sorting `(time, rowKind, id)` in display order.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineTieBoundaryTest {
    private val f = StoreFixture(recordSql = false)
    private val entries = TimelineEntries(f.db, f.reader)
    private lateinit var expected: List<TimelineKey>

    @After fun tearDown() = f.close()

    @Before fun setUp() = runBlocking {
        f.scan(1L)
        // At each of four times: five facts; three rows at the first three times; plus lone facts and rows.
        val times = listOf(BASE + 4_000, BASE + 3_000, BASE + 2_000, BASE + 1_000)
        val factTimes = times.flatMap { t -> List(5) { t } } + listOf(BASE + 3_500, BASE + 500)
        val factIds = f.persist(1L, "security_log", factTimes.mapIndexed { i, t ->
            StoreRecord(WriterFixture.securityLine(time = t).fields, "210001 $i $t")
        }, source = TelemetrySource.INTRUSION_LOG_IMPORT).factIdByChunkIndex.toList()
        f.setState(1L, ScanState.COMPLETE)
        val dao = f.db.forensicTimelineEventDao()
        fun row(t: Long, recordId: Long? = null) = ForensicTimelineEvent(startTimestamp = t, source = "app_scanner",
            category = "app_risk", description = "r$t", ruleId = "r", scanResultId = 1L, recordId = recordId)
        val rowTimes = times.take(3).flatMap { t -> List(3) { t } } + listOf(BASE + 2_500)
        val rowIds = dao.insertAll(rowTimes.map { row(it) })
        // Two finding rows whose evidence is a fact at their own time: those facts are nested, not listed.
        val nested = listOf(factIds[0], factIds[5])
        val findingIds = dao.insertAll(nested.map { row(factTimes[factIds.indexOf(it)], recordId = it) })
        expected = (rowTimes.zip(rowIds) + nested.map { factTimes[factIds.indexOf(it)] }.zip(findingIds))
            .map { (t, id) -> TimelineKey(t, TimelineRowEntity.ROW, id) } +
            factTimes.zip(factIds).filter { it.second !in nested }
                .map { (t, id) -> TimelineKey(t, TimelineRowEntity.FACT, id) }
        expected = expected.sortedWith(TimelineKey.DISPLAY_ORDER)
    }

    private fun source() = TimelinePagingSource(f.db, TimelineFilter(), entries)

    private suspend fun load(params: PagingSource.LoadParams<TimelineKey>) =
        source().load(params) as PagingSource.LoadResult.Page<TimelineKey, TimelineRow.Entry>

    private suspend fun appendFrom(page: PagingSource.LoadResult.Page<TimelineKey, TimelineRow.Entry>, size: Int):
        List<TimelineKey> {
        val out = page.data.map { it.key }.toMutableList()
        var next = page.nextKey
        while (next != null) {
            assertTrue("the append walk does not end (an entry repeats)", out.size <= expected.size + size)
            val p = load(PagingSource.LoadParams.Append(next, size, false))
            out += p.data.map { it.key }
            next = p.nextKey
        }
        return out
    }

    @Test
    fun `append walks from the top return every entry once, at every page size`() = runBlocking {
        assertEquals(32, expected.size)
        for (size in 1..expected.size + 1) {
            val walked = appendFrom(load(PagingSource.LoadParams.Refresh(null, size, false)), size)
            assertEquals("page size $size", expected, walked)
        }
    }

    @Test
    fun `a refresh at any key, then prepends and appends, returns every entry once`() = runBlocking {
        for (size in listOf(1, 2, 3, 4, 5, 7, 8)) {
            for ((i, key) in expected.withIndex()) {
                val refreshed = load(PagingSource.LoadParams.Refresh(key, size, false))
                assertEquals("refresh is inclusive at the anchor (size $size, key $i)", key, refreshed.data.first().key)
                val before = ArrayList<TimelineKey>()
                var prev = refreshed.prevKey
                while (prev != null) {
                    assertTrue("the prepend walk does not end (an entry repeats)", before.size <= expected.size + size)
                    val p = load(PagingSource.LoadParams.Prepend(prev, size, false))
                    before.addAll(0, p.data.map { it.key })
                    prev = p.prevKey
                }
                assertEquals("size $size, key $i", expected, before + appendFrom(refreshed, size))
            }
        }
    }

    /**
     * Re-review n4: under the scan filter the fact arm breaks ties on `scan_record`'s rowid, not the
     * fact id. Facts here are observed in id order, so the expected entries are the same.
     */
    @Test
    fun `the scan-filter shape walks ties without skips or duplicates`() = runBlocking {
        val scanFilter = TimelineFilter(scanId = 1L)
        fun ids(page: List<TimelineRow.Entry>) = page.map { it.entity.rowKind to it.entity.id }
        val want = expected.map { it.rowKind to it.seq }
        for (size in 1..expected.size + 1) {
            val s = TimelineEntries(f.db, f.reader)
            val walked = ArrayList<Pair<Int, Long>>()
            var page = s.page(scanFilter, null, com.androdr.data.db.TimelineDirection.FROM, size)
            walked += ids(page.items)
            while (page.keys.size == size) {
                assertTrue("the walk does not end", walked.size <= expected.size + size)
                page = s.page(scanFilter, page.keys.last(), com.androdr.data.db.TimelineDirection.AFTER, size)
                walked += ids(page.items)
            }
            assertEquals("page size $size", want, walked)
            // And back up from the end, nearest first.
            val back = ArrayList<Pair<Int, Long>>()
            var up = s.page(scanFilter, null, com.androdr.data.db.TimelineDirection.BEFORE, size)
            back += ids(up.items)
            while (up.keys.size == size) {
                assertTrue("the walk does not end", back.size <= expected.size + size)
                up = s.page(scanFilter, up.keys.last(), com.androdr.data.db.TimelineDirection.BEFORE, size)
                back += ids(up.items)
            }
            assertEquals("reverse, page size $size", want.reversed(), back)
        }
    }

    private companion object {
        const val BASE = 1_729_000_000_000L
    }
}
