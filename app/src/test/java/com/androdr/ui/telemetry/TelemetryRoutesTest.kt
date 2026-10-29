package com.androdr.ui.telemetry

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.factRoute
import com.androdr.telemetryForScan
import com.androdr.telemetryForService
import com.androdr.ui.history.offersTelemetry
import com.androdr.ui.timeline.FactTarget
import com.androdr.ui.timeline.matchedRecordTarget
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The browser's routes (spec §8.1): History and scan headers open `telemetry/{scanId}`, a service
 * opens `telemetry/{scanId}/{service}`, and "Matched record" opens `fact/{factId}` by `recordId`
 * (spec §6); a fact opened from a scan's records carries that scan.
 */
@RunWith(RobolectricTestRunner::class)
class TelemetryRoutesTest {

    @Test
    fun `routes carry the scan, service and fact ids`() {
        assertEquals("telemetry/42", telemetryForScan(42L))
        assertEquals("telemetry/42/app_scanner", telemetryForService(42L, "app_scanner"))
        assertEquals("fact/7", factRoute(7L))
        assertEquals("fact/7?scan=42", factRoute(7L, 42L))
        assertEquals("a pinned orphan (scan -1) opens without a scan", "fact/7",
            factRoute(7L, TelemetryBrowserViewModel.NO_SCAN))
    }

    @Test
    fun `a service name is path-encoded`() {
        assertEquals("telemetry/1/a%2Fb%3Fc", telemetryForService(1L, "a/b?c"))
    }

    private fun row(recordId: Long?, scanId: Long) = ForensicTimelineEvent(startTimestamp = 1L, source = "test",
        category = "finding", description = "d", recordId = recordId, scanResultId = scanId)

    @Test
    fun `Matched record opens the row's recordId as the row's scan observed it`() {
        assertEquals(FactTarget(7L, 42L), matchedRecordTarget(row(7L, 42L)))
        assertEquals("a scan-less row (-1) opens the fact without a scan", FactTarget(7L, null),
            matchedRecordTarget(row(7L, -1L)))
        assertNull("no matched record, nothing to open", matchedRecordTarget(row(null, 42L)))
    }

    @Test
    fun `History offers View telemetry only for a COMPLETE scan`() {
        for (state in ScanState.entries) {
            val scan = ScanResult(id = 1L, timestamp = 1L, bugReportFindings = emptyList(),
                riskySideloadCount = 0, knownMalwareCount = 0, state = state)
            assertEquals(state.name, state == ScanState.COMPLETE, offersTelemetry(scan))
        }
    }
}
