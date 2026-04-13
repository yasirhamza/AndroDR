package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DateGroupBuilderTest {

    // 2026-04-10 12:00:00 UTC
    private val day1Noon = 1_744_286_400_000L
    // 2026-04-10 14:00:00 UTC
    private val day1Afternoon = day1Noon + 2 * 3_600_000L
    // 2026-04-09 12:00:00 UTC (previous day)
    private val day2Noon = day1Noon - 24 * 3_600_000L

    private fun event(id: Long, ts: Long, ruleId: String = "") = ForensicTimelineEvent(
        id = id,
        startTimestamp = ts,
        source = "test",
        category = "test",
        description = "event $id",
        ruleId = ruleId,
    )

    private fun telemetryRow(id: Long, ts: Long, ruleId: String = "") =
        TimelineRow.TelemetryRow(event = event(id, ts, ruleId))

    private fun findingRow(
        ruleId: String,
        anchorTs: Long,
        anchorId: Long = anchorTs,
        level: String = "HIGH",
    ): TimelineRow.FindingRow {
        val anchor = event(anchorId, anchorTs, ruleId)
        return TimelineRow.FindingRow(
            finding = Finding(
                ruleId = ruleId,
                title = "Finding for $ruleId",
                level = level,
                category = FindingCategory.APP_RISK,
            ),
            anchorEvent = anchor,
        )
    }

    @Test
    fun `empty input returns empty list`() {
        assertEquals(emptyList<DateGroup>(), buildDateGroups(emptyList()))
    }

    @Test
    fun `telemetry rows on same day grouped into one DateGroup`() {
        val rows: List<TimelineRow> = listOf(
            telemetryRow(1, day1Noon),
            telemetryRow(2, day1Afternoon),
        )

        val groups = buildDateGroups(rows)

        assertEquals(1, groups.size)
        assertEquals(0, groups[0].findingRows.size)
        assertTrue(groups[0].standaloneRows.size + groups[0].clusters.sumOf { it.events.size } == 2)
    }

    @Test
    fun `events on different days produce separate DateGroups sorted newest first`() {
        val rows: List<TimelineRow> = listOf(
            telemetryRow(1, day2Noon),
            telemetryRow(2, day1Noon),
        )

        val groups = buildDateGroups(rows)

        assertEquals(2, groups.size)
        val newestGroupTs = groups[0].standaloneRows.maxOfOrNull { it.timestamp }
            ?: groups[0].clusters.flatMap { it.events }.maxOfOrNull { it.startTimestamp } ?: 0L
        val oldestGroupTs = groups[1].standaloneRows.maxOfOrNull { it.timestamp }
            ?: groups[1].clusters.flatMap { it.events }.maxOfOrNull { it.startTimestamp } ?: 0L
        assertTrue("Newest group first", newestGroupTs > oldestGroupTs)
    }

    @Test
    fun `finding rows land in correct date group`() {
        val rows: List<TimelineRow> = listOf(
            findingRow("androdr-001", anchorTs = day1Noon, anchorId = 10),
            telemetryRow(1, day2Noon),
        )

        val groups = buildDateGroups(rows)

        assertEquals(2, groups.size)
        val groupWithFinding = groups.first { it.findingRows.isNotEmpty() }
        assertEquals(1, groupWithFinding.findingRows.size)
        assertEquals("androdr-001", groupWithFinding.findingRows[0].finding.ruleId)
    }

    @Test
    fun `severity filter pre-filtering works - only FindingRows survive`() {
        val allRows: List<TimelineRow> = listOf(
            findingRow("androdr-001", anchorTs = day1Noon, anchorId = 10, level = "HIGH"),
            findingRow("androdr-002", anchorTs = day1Afternoon, anchorId = 11, level = "LOW"),
            telemetryRow(1, day1Noon),
        )

        val severitySet = setOf("HIGH")
        val filtered = allRows.filter { row ->
            row is TimelineRow.FindingRow &&
                row.finding.level.uppercase() in severitySet
        }

        val groups = buildDateGroups(filtered)

        assertEquals(1, groups.size)
        assertEquals(1, groups[0].findingRows.size)
        assertEquals("HIGH", groups[0].findingRows[0].finding.level)
        assertEquals(0, groups[0].standaloneRows.size)
        assertEquals(0, groups[0].clusters.size)
    }
}
