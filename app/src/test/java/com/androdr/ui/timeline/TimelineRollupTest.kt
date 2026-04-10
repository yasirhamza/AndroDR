package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the [rollUpFindings] helper that deduplicates finding rows
 * by (ruleId, packageName) for the timeline display.
 */
class TimelineRollupTest {

    private fun event(id: Long, ts: Long, ruleId: String = "") = ForensicTimelineEvent(
        id = id,
        startTimestamp = ts,
        source = "test",
        category = "test",
        description = "event $id",
        ruleId = ruleId
    )

    private fun findingRow(
        ruleId: String,
        packageName: String = "",
        anchorTs: Long = 1_000L,
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
                matchContext = if (packageName.isNotEmpty()) {
                    mapOf("package_name" to packageName)
                } else {
                    emptyMap()
                }
            ),
            anchorEvent = anchor,
        )
    }

    private fun telemetryRow(id: Long, ts: Long): TimelineRow.TelemetryRow {
        return TimelineRow.TelemetryRow(event = event(id, ts))
    }

    @Test
    fun `groups by ruleId and packageName - 3 same rule same package yield 1 row with count 3`() {
        val rows = listOf(
            findingRow("androdr-001", "com.example", anchorTs = 1_000L, anchorId = 1),
            findingRow("androdr-001", "com.example", anchorTs = 2_000L, anchorId = 2),
            findingRow("androdr-001", "com.example", anchorTs = 3_000L, anchorId = 3),
        )

        val result = rollUpFindings(rows)
        val findings = result.filterIsInstance<TimelineRow.FindingRow>()

        assertEquals(1, findings.size)
        assertEquals(3, findings[0].duplicateCount)
        assertEquals(1_000L, findings[0].firstSeenTimestamp)
    }

    @Test
    fun `different rules on same package stay separate`() {
        val rows = listOf(
            findingRow("androdr-001", "com.example", anchorTs = 1_000L, anchorId = 1),
            findingRow("androdr-002", "com.example", anchorTs = 2_000L, anchorId = 2),
        )

        val result = rollUpFindings(rows)
        val findings = result.filterIsInstance<TimelineRow.FindingRow>()

        assertEquals(2, findings.size)
    }

    @Test
    fun `different packages with same rule stay separate`() {
        val rows = listOf(
            findingRow("androdr-001", "com.example.a", anchorTs = 1_000L, anchorId = 1),
            findingRow("androdr-001", "com.example.b", anchorTs = 2_000L, anchorId = 2),
        )

        val result = rollUpFindings(rows)
        val findings = result.filterIsInstance<TimelineRow.FindingRow>()

        assertEquals(2, findings.size)
    }

    @Test
    fun `single occurrence has duplicateCount 1`() {
        val rows = listOf(
            findingRow("androdr-001", "com.example", anchorTs = 5_000L, anchorId = 1),
        )

        val result = rollUpFindings(rows)
        val findings = result.filterIsInstance<TimelineRow.FindingRow>()

        assertEquals(1, findings.size)
        assertEquals(1, findings[0].duplicateCount)
    }

    @Test
    fun `telemetry rows unaffected by rollup`() {
        val rows: List<TimelineRow> = listOf(
            telemetryRow(1, 1_000L),
            telemetryRow(2, 2_000L),
            findingRow("androdr-001", "com.example", anchorTs = 3_000L, anchorId = 3),
            findingRow("androdr-001", "com.example", anchorTs = 4_000L, anchorId = 4),
        )

        val result = rollUpFindings(rows)
        val telemetry = result.filterIsInstance<TimelineRow.TelemetryRow>()
        val findings = result.filterIsInstance<TimelineRow.FindingRow>()

        assertEquals(2, telemetry.size)
        assertEquals(1, findings.size)
        assertEquals(2, findings[0].duplicateCount)
    }

    @Test
    fun `most recent occurrence wins timestamp`() {
        val rows = listOf(
            findingRow("androdr-001", "com.example", anchorTs = 1_000L, anchorId = 1),
            findingRow("androdr-001", "com.example", anchorTs = 5_000L, anchorId = 2),
            findingRow("androdr-001", "com.example", anchorTs = 3_000L, anchorId = 3),
        )

        val result = rollUpFindings(rows)
        val findings = result.filterIsInstance<TimelineRow.FindingRow>()

        assertEquals(1, findings.size)
        assertEquals(5_000L, findings[0].timestamp)
        assertEquals(1_000L, findings[0].firstSeenTimestamp)
        assertEquals(3, findings[0].duplicateCount)
    }

    @Test
    fun `result is sorted descending by timestamp`() {
        val rows: List<TimelineRow> = listOf(
            telemetryRow(1, 6_000L),
            findingRow("androdr-001", "com.example", anchorTs = 3_000L, anchorId = 2),
            telemetryRow(3, 1_000L),
        )

        val result = rollUpFindings(rows)

        for (i in 0 until result.size - 1) {
            assertTrue(
                "Row $i (ts=${result[i].timestamp}) should be >= row ${i + 1} (ts=${result[i + 1].timestamp})",
                result[i].timestamp >= result[i + 1].timestamp
            )
        }
    }
}
