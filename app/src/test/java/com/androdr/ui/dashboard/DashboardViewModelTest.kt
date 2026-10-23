package com.androdr.ui.dashboard

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.sigma.SigmaCorrelationEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The "Correlation incomplete" warning (spec §5.2): a distinct Dashboard warning naming the rule and
 * the package, separate from the scanner-failure banner — nothing failed, an app can cause it.
 */
class DashboardViewModelTest {

    private val cut = ScannerFailure(
        scanner = SigmaCorrelationEngine.SCANNER,
        exception = NotEvaluatedReason.CORRELATION_INCOMPLETE.sentinel,
        message = "Permission then C2 (androdr-corr-003): not finished in time for com.flood",
        ruleId = "androdr-corr-003",
        packages = listOf("com.flood"),
    )

    private fun scan(vararg errors: ScannerFailure) = ScanResult(
        id = 1L, timestamp = 1L, findings = emptyList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = errors.toList(),
    )

    @Test
    fun `the warning names the rule and the package and the scanner-failure banner stays hidden`() {
        val s = scan(cut)

        val lines = DashboardViewModel.correlationIncomplete(s, isScanning = false)

        assertEquals(1, lines.size)
        assertTrue(lines.single(), lines.single().contains("com.flood"))
        assertTrue(lines.single(), lines.single().contains("androdr-corr-003"))
        assertFalse("the scanner-failure banner is hidden", s.isPartialScan)
        assertEquals(0, s.realFailureCount)
    }

    @Test
    fun `no warning while scanning, without a scan, or for other skips`() {
        assertTrue(DashboardViewModel.correlationIncomplete(scan(cut), isScanning = true).isEmpty())
        assertTrue(DashboardViewModel.correlationIncomplete(null, isScanning = false).isEmpty())
        val other = cut.copy(exception = NotEvaluatedReason.NO_EVENTS_TO_CHECK.sentinel)
        assertTrue(DashboardViewModel.correlationIncomplete(scan(other), isScanning = false).isEmpty())
    }
}
