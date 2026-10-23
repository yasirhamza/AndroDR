package com.androdr.data.db

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
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * C4 scan filter (replaces C3's uncapped stopgap): one scan's visible rows and the event facts it
 * observed, read through `scan_record(scanId, eventTime)`, newest first, uncapped; nothing of a
 * hidden scan, nothing of another scan.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineScanFilterTest {
    private val f = StoreFixture()
    private val dao get() = f.db.timelineDao()

    @After fun tearDown() = f.close()

    private fun row(scan: Long, t: Long) = ForensicTimelineEvent(startTimestamp = t, source = "s", category = "c",
        description = "$scan@$t", scanResultId = scan)

    private fun line(i: Long, t: Long) =
        StoreRecord(WriterFixture.securityLine(time = t).fields, "210001 $i $t")

    private suspend fun all(filter: TimelineFilter): List<TimelineRowEntity> {
        val out = ArrayList<TimelineRowEntity>()
        var key: TimelineKey? = null
        while (true) {
            val page = dao.page(filter, key, if (key == null) TimelineDirection.FROM else TimelineDirection.AFTER, 97)
            out += page
            if (page.size < 97) return out
            key = page.last().key
        }
    }

    @Test
    fun `the scan filter reads one scan's rows and observed facts, newest first, with no cap`() = runBlocking {
        f.scan(1L)
        f.scan(2L)
        f.scan(3L)
        f.persist(1L, "security_log", (1L..700L).map { line(it, it * 2) },
            source = TelemetrySource.INTRUSION_LOG_IMPORT)
        f.persist(2L, "security_log", listOf(line(9_001L, 5L)), source = TelemetrySource.INTRUSION_LOG_IMPORT)
        f.persist(3L, "security_log", listOf(line(9_002L, 7L)), source = TelemetrySource.INTRUSION_LOG_IMPORT)
        f.setState(1L, ScanState.COMPLETE)
        f.setState(2L, ScanState.COMPLETE)
        f.db.forensicTimelineEventDao().insertAll((1L..600L).map { row(1L, it * 2 + 1) } + row(2L, 5L) +
            row(3L, 5L) + row(-1L, 5L))

        val got = all(TimelineFilter(scanId = 1L))

        assertEquals("every row and fact of the scan, past the old 500 cap", 1_300, got.size)
        assertEquals(600, got.count { it.rowKind == TimelineRowEntity.ROW })
        assertTrue("all of scan 1", got.all { it.scanId == 1L })
        assertEquals(got.map { it.key }.sortedWith(TimelineKey.DISPLAY_ORDER), got.map { it.key })
        assertEquals(1_300L, dao.count(TimelineFilter(scanId = 1L)))
        assertEquals("an IN_PROGRESS scan shows nothing", emptyList<TimelineRowEntity>(),
            all(TimelineFilter(scanId = 3L)))
        assertEquals(0L, dao.count(TimelineFilter(scanId = 3L)))
    }
}
