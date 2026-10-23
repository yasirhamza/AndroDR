package com.androdr.ui.timeline

import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.ForensicTimelineEvent
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
 * The Timeline export streams the union page by page (spec §7) with no row cap, and writes what the
 * screen shows: every row, every standalone event, and each row's nested evidence right after it
 * (C4 review I3), so every `record_id` resolves within the file and the export total is the count.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineExportStreamTest {
    private val f = StoreFixture(recordSql = false)
    private val entries = TimelineEntries(f.db, f.reader)

    @After fun tearDown() = f.close()

    private suspend fun persist(n: Long): List<Long> {
        f.scan(1L)
        val ids = f.persist(1L, "security_log", (0L until n).map { i ->
            StoreRecord(WriterFixture.securityLine(time = BASE + i).fields, "210001 $i ${BASE + i}")
        }, source = TelemetrySource.INTRUSION_LOG_IMPORT).factIdByChunkIndex.toList()
        f.setState(1L, ScanState.COMPLETE)
        return ids
    }

    /** CSV data lines of the whole Timeline, oldest first. */
    private suspend fun csvRows(): List<List<String>> {
        val csv = StringBuilder()
        TimelineExporter.writeCsvHeader(csv)
        entries.forEachPage(TimelineFilter(), oldestFirst = true, size = 500) { page ->
            assertTrue("one page held at a time", page.size <= 500)
            page.flatMap { it.exportEvents() }.forEach { TimelineExporter.writeCsvRow(csv, it) }
        }
        return csv.lines().drop(1).filter { it.isNotEmpty() }.map { it.split(",") }
    }

    @Test
    fun `the CSV export streams every event, oldest first, past the old 10,000 cap`() = runBlocking {
        persist(N)
        val rows = csvRows()

        assertEquals(N.toInt(), rows.size)
        assertEquals((0L until N).map { BASE + it }, rows.map { it[0].toLong() })
        var newestFirst = 0
        entries.forEachPage(TimelineFilter(), oldestFirst = false, size = 500) { newestFirst += it.size }
        assertEquals(N.toInt(), newestFirst)
    }

    @Test
    fun `nested evidence is exported after its row, so every record_id resolves and totals match`() = runBlocking {
        val ids = persist(1_000L)
        val evidence = listOf(ids[10], ids[500], ids[999])
        f.db.forensicTimelineEventDao().insertAll(evidence.map { id ->
            ForensicTimelineEvent(startTimestamp = BASE + ids.indexOf(id), source = "app_scanner",
                category = "app_risk",
                description = "hit", ruleId = "r", scanResultId = 1L, recordId = id)
        })
        val rows = csvRows()
        val count = entries.count(TimelineFilter())

        assertEquals("the export holds what the screen counts", count, rows.size.toLong())
        assertEquals(1_003L, count)
        val recordIdCol = TimelineExporter.CSV_HEADER.split(",").indexOf("record_id")
        val ruleCol = TimelineExporter.CSV_HEADER.split(",").indexOf("rule_id")
        val facts = rows.filter { it[ruleCol].isEmpty() }.map { it[recordIdCol].toLong() }
        assertEquals("every fact exported once", ids.toSet(), facts.toSet())
        assertEquals(ids.size, facts.size)
        val findings = rows.withIndex().filter { it.value[ruleCol].isNotEmpty() }
        assertEquals(3, findings.size)
        for ((i, row) in findings) {
            assertEquals("the evidence line follows its row", row[recordIdCol], rows[i + 1][recordIdCol])
        }
        val stats = TimelineExporter.PlaintextStats(emptyMap())
        entries.forEachPage(TimelineFilter(), oldestFirst = false, size = 500) { page ->
            page.forEach { e -> e.exportEvents().forEach(stats::add) }
        }
        assertEquals("the plaintext total is the on-screen count", count, stats.total)
    }

    private companion object {
        const val N = 12_000L
        const val BASE = 1_729_000_000_000L
    }
}
