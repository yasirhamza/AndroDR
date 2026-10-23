package com.androdr.data.db

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.store.StoreFixture
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * C3: the import screen links to the Timeline filtered to the import's scan. The scan filter's
 * read returns exactly that scan's visible rows, uncapped, and nothing of a hidden scan.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineScanFilterTest {
    private val f = StoreFixture()

    @After fun tearDown() = f.close()

    private fun row(scan: Long, t: Long) = ForensicTimelineEvent(startTimestamp = t, source = "s", category = "c",
        description = "$scan@$t", scanResultId = scan)

    @Test
    fun `the scan filter reads one scan's visible rows, newest first, with no cap`() = runBlocking {
        f.scan(1L, ScanState.COMPLETE)
        f.scan(2L, ScanState.COMPLETE)
        f.scan(3L, ScanState.IN_PROGRESS)
        val dao = f.db.forensicTimelineEventDao()
        dao.insertAll((1L..600L).map { row(1L, it) } + row(2L, 5L) + row(3L, 5L) + row(-1L, 5L))

        val rows = dao.getEventsByScan(1L).first()

        assertEquals("every row of the scan, past the old 500 cap", 600, rows.size)
        assertEquals((600L downTo 1L).toList(), rows.map { it.startTimestamp })
        assertEquals(emptyList<ForensicTimelineEvent>(), dao.getEventsByScan(3L).first())
    }
}
