package com.androdr.ui.timeline

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
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.time.ZoneOffset

/**
 * C4 re-review n6: a day header counts what that day shows. A finding row on day 2 whose evidence
 * fact is from day 1 shows the fact nested under the row, in day 2's group: day 2 counts both,
 * day 1 counts neither (before, day 1 also counted the fact, so the two headers summed to more
 * than the list).
 */
@RunWith(RobolectricTestRunner::class)
class TimelineDayHeaderCountTest {
    private val f = StoreFixture(recordSql = false)

    @After fun tearDown() = f.close()

    @Test
    fun `cross-day evidence counts under its row's day only`() = runBlocking {
        val day1 = 1_774_656_000_000L + 3_600_000L
        val day2 = day1 + 86_400_000L
        f.scan(1L)
        val (evidence, lone) = f.persist(1L, "security_log", listOf(day1, day1 + 60_000L).mapIndexed { i, t ->
            StoreRecord(WriterFixture.securityLine(time = t).fields, "210001 $i $t")
        }, source = TelemetrySource.INTRUSION_LOG_IMPORT).factIdByChunkIndex.toList()
        f.setState(1L, ScanState.COMPLETE)
        f.db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = day2, source = "app_scanner",
            category = "app_risk", description = "hit", ruleId = "r", scanResultId = 1L, recordId = evidence))
        val entries = TimelineEntries(f.db, f.reader)
        val filter = TimelineFilter(zone = ZoneOffset.UTC)

        assertEquals("the row and its nested evidence", 2L, entries.count(filter.forDay(filter.dayOf(day2))))
        assertEquals("only the lone fact (id $lone)", 1L, entries.count(filter.forDay(filter.dayOf(day1))))
        assertEquals(3L, entries.count(filter))
    }
}
