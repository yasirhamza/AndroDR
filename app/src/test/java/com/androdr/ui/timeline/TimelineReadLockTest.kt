package com.androdr.ui.timeline

import com.androdr.data.db.TimelineDirection
import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
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
 * C4 review I4: Timeline reads never take a Room transaction. A Room transaction (`@Transaction`,
 * `withTransaction`) holds the single writer connection, so a long count would stall an import's
 * chunk commits and the DNS monitor's inserts. Room's query callback logs every transaction it opens
 * (`BEGIN … TRANSACTION`); a page, a count and an export walk must log none, and each page and each
 * count is ONE statement (one consistent read).
 */
@RunWith(RobolectricTestRunner::class)
class TimelineReadLockTest {
    private val f = StoreFixture()
    private val entries = TimelineEntries(f.db, f.reader)

    @After fun tearDown() = f.close()

    @Test
    fun `pages, counts and export walks run without a transaction, one statement each`() = runBlocking {
        f.scan(1L)
        val ids = f.persist(1L, "security_log", (0L until 50L).map { i ->
            StoreRecord(WriterFixture.securityLine(time = BASE + i).fields, "210001 $i ${BASE + i}")
        }, source = TelemetrySource.INTRUSION_LOG_IMPORT).factIdByChunkIndex.toList()
        f.setState(1L, ScanState.COMPLETE)
        f.db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = BASE + 5, source = "app_scanner",
            category = "app_risk", description = "hit", ruleId = "r", scanResultId = 1L, recordId = ids[5]))
        val filters = listOf(TimelineFilter(), TimelineFilter(scanId = 1L), TimelineFilter(levels = setOf("HIGH")))
        // Let Room's asynchronous invalidation refresh (after the inserts above) finish before recording.
        Thread.sleep(200)
        f.db.invalidationTracker.refreshVersionsSync()
        f.sql.clear()

        for (filter in filters) {
            entries.page(filter, null, TimelineDirection.FROM, 10)
            entries.count(filter)
            entries.forEachPage(filter, oldestFirst = true, size = 7) { }
        }
        val sql = synchronized(f.sql) { f.sql.toList() }

        assertTrue(sql.isNotEmpty())
        val tx = sql.filter { it.trim().uppercase().startsWith("BEGIN") }
        assertTrue("Timeline reads opened transactions: $tx", tx.isEmpty())
        val countStatements = sql.filter { it.startsWith("SELECT (SELECT COUNT(*)") }
        assertEquals("one statement per count", filters.size, countStatements.size)
    }

    private companion object {
        const val BASE = 1_729_000_000_000L
    }
}
