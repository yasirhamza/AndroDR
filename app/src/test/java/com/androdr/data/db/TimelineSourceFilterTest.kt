package com.androdr.data.db

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TimelineRowEntity
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.StoreFixture.Companion.dns
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * C4 review m4, fixed in C5: the source filter means one thing in both arms — the telemetry source
 * ([TelemetrySource]) of a row (`forensic_timeline.telemetrySource`) and of a fact's visible
 * observation (`scan_record.source`; a pinned orphan's `firstSource`). It used to match a row's
 * producing module (`source`) but a fact's service, so one value could never select both.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineSourceFilterTest {
    private val f = StoreFixture(recordSql = false)
    private val dao get() = f.db.timelineDao()

    @After fun tearDown() = f.close()

    private fun row(t: Long, source: TelemetrySource, scan: Long) = ForensicTimelineEvent(startTimestamp = t,
        source = "dns_monitor", category = "ioc_match", description = "$source@$t", telemetrySource = source,
        scanResultId = scan)

    private suspend fun all(filter: TimelineFilter): List<TimelineRowEntity> {
        val got = dao.page(filter, null, TimelineDirection.FROM, 1_000)
        assertEquals("the count is what pages for $filter", got.size.toLong(), dao.count(filter))
        return got
    }

    private fun List<TimelineRowEntity>.times() = map { it.time }.toSet()

    @Test
    fun `the source filter selects rows and facts of one telemetry source alike`() = runBlocking {
        f.scan(1L)
        f.persist(1L, "dns_monitor", listOf(dns("live.example", time = 100L)), source = TelemetrySource.LIVE_SCAN)
        f.setState(1L, ScanState.COMPLETE)
        f.scan(2L)
        f.persist(2L, "dns_monitor", listOf(dns("import.example", time = 200L)),
            source = TelemetrySource.BUGREPORT_IMPORT)
        f.setState(2L, ScanState.COMPLETE)
        // One fact observed by both: created by the live scan 3, then seen again by import 4.
        f.scan(3L)
        f.persist(3L, "dns_monitor", listOf(dns("both.example", time = 300L)), source = TelemetrySource.LIVE_SCAN)
        f.setState(3L, ScanState.COMPLETE)
        f.scan(4L)
        f.persist(4L, "dns_monitor", listOf(dns("both.example", time = 300L)),
            source = TelemetrySource.BUGREPORT_IMPORT)
        f.setState(4L, ScanState.COMPLETE)
        // The live scan that created the shared fact is gone; only the import still observes it.
        f.db.openHelper.writableDatabase.execSQL("DELETE FROM scan_record WHERE scanId = 3")
        val rows = f.db.forensicTimelineEventDao()
        rows.insert(row(110L, TelemetrySource.LIVE_SCAN, 1L))
        rows.insert(row(210L, TelemetrySource.BUGREPORT_IMPORT, 2L))

        val imported = all(TimelineFilter(source = TelemetrySource.BUGREPORT_IMPORT))
        assertEquals("the import's row, its fact, and the fact it still observes", setOf(200L, 210L, 300L),
            imported.times())
        assertEquals(setOf(100L, 110L), all(TimelineFilter(source = TelemetrySource.LIVE_SCAN)).times())
        assertEquals("under a scan filter: that scan's observation source", setOf(200L, 210L),
            all(TimelineFilter(scanId = 2L, source = TelemetrySource.BUGREPORT_IMPORT)).times())
        assertEquals(emptySet<Long>(), all(TimelineFilter(scanId = 2L, source = TelemetrySource.LIVE_SCAN)).times())
        assertEquals(emptySet<Long>(), all(TimelineFilter(source = TelemetrySource.INTRUSION_LOG_IMPORT)).times())
    }

    @Test
    fun `a pinned orphan matches by the source that created it`() = runBlocking {
        f.scan(1L)
        val fact = f.persist(1L, "dns_monitor", listOf(dns("orphan.example", time = 100L)),
            source = TelemetrySource.BUGREPORT_IMPORT).factIdByChunkIndex.single()
        f.setState(1L, ScanState.COMPLETE)
        f.db.openHelper.writableDatabase.execSQL("DELETE FROM scan_record WHERE scanId = 1")
        f.pinBySignal(fact)

        assertEquals(setOf(100L), all(TimelineFilter(source = TelemetrySource.BUGREPORT_IMPORT)).times())
        assertEquals(emptySet<Long>(), all(TimelineFilter(source = TelemetrySource.LIVE_SCAN)).times())
    }
}
