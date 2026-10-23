package com.androdr.ui.timeline

import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.StoreFixture
import com.androdr.reporting.TimelineExporter
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
 * The Timeline export streams the union page by page (spec §7) with no row cap: the CSV holds
 * every event past the old `LIMIT 10000`, oldest first, and the newest-first pass visits the same.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineExportStreamTest {
    private val f = StoreFixture(recordSql = false)

    @After fun tearDown() = f.close()

    @Test
    fun `the CSV export streams every event, oldest first, past the old 10,000 cap`() = runBlocking {
        f.scan(1L)
        f.persist(1L, "security_log", (0L until N).map { i ->
            StoreRecord(WriterFixture.securityLine(time = BASE + i).fields, "210001 $i ${BASE + i}")
        }, source = TelemetrySource.INTRUSION_LOG_IMPORT)
        f.setState(1L, ScanState.COMPLETE)
        val entries = TimelineEntries(f.db, f.reader)
        val csv = StringBuilder()
        var largestPage = 0
        TimelineExporter.writeCsvHeader(csv)
        entries.forEachPage(TimelineFilter(), oldestFirst = true, size = 500) { page ->
            largestPage = maxOf(largestPage, page.size)
            page.forEach { TimelineExporter.writeCsvRow(csv, it.asExportEvent()) }
        }
        val rows = csv.lines().drop(1).filter { it.isNotEmpty() }

        assertEquals(N.toInt(), rows.size)
        val times = rows.map { it.substringBefore(",").toLong() }
        assertEquals((0L until N).map { BASE + it }, times)
        assertTrue("one page held at a time", largestPage <= 500)
        var newestFirst = 0
        entries.forEachPage(TimelineFilter(), oldestFirst = false, size = 500) { newestFirst += it.size }
        assertEquals(N.toInt(), newestFirst)
    }

    private companion object {
        const val N = 12_000L
        const val BASE = 1_729_000_000_000L
    }
}
