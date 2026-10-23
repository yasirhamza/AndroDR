package com.androdr.ui.timeline

import com.androdr.reporting.appendStoredTelemetry
import com.androdr.reporting.ReportOut
import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.TelemetrySource
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import com.androdr.reporting.TimelineExporter
import com.androdr.scanner.WriterFixture
import com.androdr.scanner.bugreport.BatteryDailyModule
import com.androdr.scanner.bugreport.DumpsysClock
import com.androdr.sigma.BugReportRecordBuilders
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.time.LocalDate
import java.time.ZoneId
import java.util.TimeZone

/**
 * Ruling R32 (C4 re-review I5) and n1: a battery day is a calendar date. Imported from a zone-less
 * report (assumed UTC) and from an Asia/Qatar report, and viewed on a device in America/Los_Angeles
 * (west of UTC, where a UTC midnight is the previous evening), the fact and the finding row on it
 * show the report's printed date everywhere: CSV `isodate`, the plaintext date section, the day it
 * groups under (`dayOf`), the detail sheet's date; and the finding row is dated at its battery day,
 * not "Unknown date" (n1).
 */
@RunWith(RobolectricTestRunner::class)
class TimelineDayPrecisionZoneTest {
    private val jvmZone: TimeZone = TimeZone.getDefault()
    private val viewer: ZoneId = ZoneId.of("America/Los_Angeles")
    private val printed: LocalDate = LocalDate.of(2026, 3, 28)
    private val resolver = mockk<IndicatorResolver> { every { isKnownBadPackage(any()) } returns null }

    private val battery = """
        Daily stats:
          Current start time: 2026-03-28-01-00-01
          Package changes:
            -pkg=com.example.gone vers=100
    """.trimIndent()

    @Before fun setUp() = TimeZone.setDefault(TimeZone.getTimeZone(viewer))

    @After fun tearDown() = TimeZone.setDefault(jvmZone)

    @Test
    fun `a zone-less report's battery day shows its printed date`() = check(DumpsysClock.ASSUMED_UTC)

    @Test
    fun `an Asia-Qatar report's battery day shows its printed date`() =
        check(DumpsysClock.fromSystemProperties("[persist.sys.timezone]: [Asia/Qatar]\n"))

    private fun check(clock: DumpsysClock) = runBlocking {
        WriterFixture(recordSql = false).use { w ->
            w.engine.setRemoteRules(listOf(
                WriterFixture.rule(RULE, "battery_daily", "event_type", "package_uninstall", "high"),
            ))
            val events = BatteryDailyModule().analyze(battery, resolver, DeviceIdentity.UNKNOWN, clock)
                .typed.batteryDailyEvents
            val s = w.writer.begin(w.scan(7L, TelemetrySource.BUGREPORT_IMPORT), liveEvents = false)
            s.appendAll("battery_daily", TelemetrySource.BUGREPORT_IMPORT, WriterFixture.IMPORT_CAPTURED,
                BugReportRecordBuilders.batteryDaily(events).asSequence())
            s.finish()

            val filter = TimelineFilter(zone = viewer)
            val all = ArrayList<TimelineRow.Entry>()
            TimelineEntries(w.f.db, w.f.reader).forEachPage(filter, oldestFirst = false, size = 10) { all += it }
            val row = all.filterIsInstance<TimelineRow.StoredRow>().single()
            val fact = row.evidence!!
            val dayStart = printed.atStartOfDay(viewer).toInstant().toEpochMilli()

            assertEquals("stored as the printed date's UTC midnight", UTC_MIDNIGHT, fact.eventTime)
            // n1: the finding row is dated at its battery day, date-only, not "Unknown date".
            assertEquals(UTC_MIDNIGHT, row.event.startTimestamp)
            assertTrue(row.entity.isDay)
            assertEquals(DATE_ONLY, rowTime(row.event))
            // I6: the Linked Evidence line never shows a made-up time of day for a day row.
            assertTrue(linkedEvidenceLabel(row.event).startsWith(DATE_ONLY))
            assertEquals("Mar 28, 2026", rowDate(row.event))
            assertEquals("the row groups under the printed date", dayStart,
                filter.dayOf(row.timestamp, row.entity.isDay))
            // The fact: detail sheet date, CSV isodate, plaintext date section.
            assertEquals("Mar 28, 2026", factDate(fact, fact.eventTime!!))
            val export = fact.asExportEvent(7L)
            val csv = StringBuilder()
            TimelineExporter.writeCsvHeader(csv)
            TimelineExporter.writeCsvRow(csv, export)
            val header = csv.lines()[0].split(",")
            assertEquals("2026-03-28", csv.lines()[1].split(",")[header.indexOf("isodate")])
            val text = TimelineExporter.formatPlaintext(listOf(export), versionName = "t")
            assertTrue(text, text.lines().any { it.trim() == "2026-03-28" })
            assertTrue(text.lines().none { it.trim() == "2026-03-27" })
            // The report's stored-telemetry section prints the same date.
            val report = StringBuilder()
            ReportOut(report).appendStoredTelemetry(w.f.db.scanResultDao().getLatestTwo().single(),
                w.f.reader.services(7L), w.f.reader)
            assertTrue(report.toString(), report.contains("event 2026-03-28"))
            // The day header counts what it shows: the row and its nested evidence.
            assertEquals(2L, TimelineEntries(w.f.db, w.f.reader).count(filter.forDay(dayStart)))
            assertEquals(0L, TimelineEntries(w.f.db, w.f.reader).count(filter.forDay(dayStart - DAY_MS)))
        }
    }

    private companion object {
        const val RULE = "androdr-t-battery"
        const val DAY_MS = 86_400_000L

        /** 2026-03-28T00:00:00Z, written out (not derived through CivilDay). */
        const val UTC_MIDNIGHT = 1_774_656_000_000L
    }
}
