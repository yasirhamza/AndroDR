package com.androdr.ui.dashboard

import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetryState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A7c: the Dashboard warns when the latest scan's records were not stored (telemetry FAILED). */
class StorageFailedBannerTest {

    private fun scan(state: TelemetryState) = ScanResult(
        id = 1L, timestamp = 1L, findings = emptyList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, telemetryState = state,
    )

    @Test
    fun `a FAILED scan shows the banner`() =
        assertTrue(DashboardViewModel.showStorageFailedBanner(scan(TelemetryState.FAILED), isScanning = false))

    @Test
    fun `stored, partial-retention and none do not`() {
        for (s in listOf(TelemetryState.STORED, TelemetryState.PARTIAL_RETENTION, TelemetryState.NONE)) {
            assertFalse("$s", DashboardViewModel.showStorageFailedBanner(scan(s), isScanning = false))
        }
    }

    @Test
    fun `no scan and a running scan show nothing`() {
        assertFalse(DashboardViewModel.showStorageFailedBanner(null, isScanning = false))
        assertFalse(DashboardViewModel.showStorageFailedBanner(scan(TelemetryState.FAILED), isScanning = true))
    }

    @Test
    fun `source gate - the dashboard renders the banner from the helper`() {
        val src = java.io.File("src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt").readText()
        assertTrue(src.contains("showStorageFailedBanner(latestScan, isScanning)"))
        assertTrue(src.contains("storage_failed_banner_body"))
    }
}
