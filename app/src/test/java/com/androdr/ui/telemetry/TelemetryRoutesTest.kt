package com.androdr.ui.telemetry

import com.androdr.factRoute
import com.androdr.telemetryForScan
import com.androdr.telemetryForService
import org.junit.Assert.assertEquals
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
}
