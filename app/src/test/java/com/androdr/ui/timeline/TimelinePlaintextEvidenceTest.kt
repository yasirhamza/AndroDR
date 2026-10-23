package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TimelineRowEntity
import com.androdr.data.store.DecodedRecord
import com.androdr.reporting.TimelineExporter
import com.androdr.sigma.TimePrecision
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * C4 re-review n5: in the newest-first plaintext export a row's nested evidence stays inside the
 * row's date section, even when the evidence is from another day, so no date header repeats.
 */
class TimelinePlaintextEvidenceTest {

    private fun entity(rowKind: Int, id: Long, time: Long, recordId: Long? = null) = TimelineRowEntity(
        rowKind = rowKind, id = id, seq = id, scanId = 1L, time = time, category = "c", packageName = "", level = null,
        ruleId = "", correlationId = "", kind = "event", telemetrySource = TelemetrySource.BUGREPORT_IMPORT,
        bodyHash = null, recordId = recordId, timePrecision = "exact",
    )

    private fun record(id: Long, time: Long) = DecodedRecord(factId = id, scanId = 1L, service = "security_log",
        ordinal = 0, source = TelemetrySource.BUGREPORT_IMPORT, capturedAt = time, eventTime = time,
        precision = TimePrecision.EXACT, category = "security_event", fields = emptyMap(), summary = "fact $id")

    /** Re-review n7: an export's filter label shows the time range as dates in the filter zone, not epoch ms. */
    @Test
    fun `the export filter label shows the range in the filter zone`() {
        val label = com.androdr.data.db.TimelineFilter(from = 1_774_656_000_000L, to = 1_774_742_399_999L,
            zone = java.time.ZoneId.of("Asia/Qatar")).describe()!!
        assertTrue(label, label.contains("2026-03-28T03:00..2026-03-29T02:59:59.999 (Asia/Qatar)"))
        assertTrue(label, !label.contains("1774656000000"))
    }

    @Test
    fun `cross-day evidence never repeats a date section`() {
        val day1 = 1_774_000_000_000L
        val day2 = day1 + 2 * 86_400_000L
        val row = TimelineRow.StoredRow(entity(TimelineRowEntity.ROW, 1L, day2, recordId = 5L),
            ForensicTimelineEvent(id = 1L, startTimestamp = day2, source = "s", category = "app_risk",
                description = "finding", ruleId = "r", recordId = 5L), record(5L, day1))
        val older = TimelineRow.EventRow(entity(TimelineRowEntity.FACT, 6L, day1 + 1), record(6L, day1 + 1))
        val stats = TimelineExporter.PlaintextStats(emptyMap())
        listOf(row, older).forEach { e -> e.exportEvents().forEach(stats::add) }
        val out = StringBuilder()
        val writer = TimelineExporter.PlaintextWriter(out)
        writer.header(stats, "t")
        writer.entry(row)
        writer.entry(older)
        writer.footer()

        val sections = out.lines().filter { Regex("""^  \d{4}-\d{2}-\d{2}$""").matches(it) }
        assertEquals("one section per day, in order: $sections", sections.distinct(), sections)
        assertEquals(2, sections.size)
        assertTrue(out.contains("Evidence: "))
    }
}
