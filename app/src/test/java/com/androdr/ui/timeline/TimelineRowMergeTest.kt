package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the pure [mergeTimelineRows] helper. Covers the
 * chronological merge and the `hideInformationalTelemetry` filter that
 * ViewModel exposes to the UI.
 */
class TimelineRowMergeTest {

    private fun event(id: Long, ts: Long, ruleId: String = "") = ForensicTimelineEvent(
        id = id,
        startTimestamp = ts,
        source = "test",
        category = "test",
        description = "event $id",
        ruleId = ruleId
    )

    private fun finding(ruleId: String, level: String = "HIGH") = Finding(
        ruleId = ruleId,
        title = "Finding for $ruleId",
        level = level,
        category = FindingCategory.APP_RISK
    )

    @Test
    fun `ViewModel emits telemetry and finding rows sorted by timestamp`() {
        val e1 = event(1, 1_000L, ruleId = "androdr-001")
        val e2 = event(2, 2_000L)
        val f = finding("androdr-001")

        val rows = mergeTimelineRows(
            events = listOf(e1, e2),
            findings = listOf(f),
            hideInformationalTelemetry = false
        )

        // 2 telemetry + 1 finding = 3 rows, sorted descending
        assertEquals(3, rows.size)
        // Highest timestamp first
        assertTrue(rows[0] is TimelineRow.TelemetryRow)
        assertEquals(2_000L, rows[0].timestamp)
        // The FindingRow with anchor e1 lands at e1's timestamp (1000)
        val findingRow = rows.filterIsInstance<TimelineRow.FindingRow>().first()
        assertEquals(1_000L, findingRow.timestamp)
        assertEquals(e1.id, findingRow.anchorEvent?.id)
    }

    @Test
    fun `hideInformationalTelemetry filter hides unreferenced telemetry rows`() {
        val referenced = event(1, 1_000L, ruleId = "androdr-001")
        val orphan = event(2, 2_000L)
        val f = finding("androdr-001")

        val off = mergeTimelineRows(
            events = listOf(referenced, orphan),
            findings = listOf(f),
            hideInformationalTelemetry = false
        )
        assertEquals("filter OFF shows all 3 rows", 3, off.size)

        val on = mergeTimelineRows(
            events = listOf(referenced, orphan),
            findings = listOf(f),
            hideInformationalTelemetry = true
        )
        assertEquals("filter ON drops the orphan telemetry row", 2, on.size)
        assertTrue(on.none {
            it is TimelineRow.TelemetryRow && it.event.id == orphan.id
        })
        // Referenced telemetry row should remain
        assertTrue(on.any {
            it is TimelineRow.TelemetryRow && it.event.id == referenced.id
        })
        // Finding row should remain
        assertTrue(on.any { it is TimelineRow.FindingRow })
    }
}
