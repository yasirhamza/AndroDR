package com.androdr.ui.dashboard

import com.androdr.data.model.RiskLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * D3 review I2/I3: alerts are current until a person closes them (spec §5.4), so the Dashboard's risk
 * badge is at least the most severe open alert, and "mostly secure" / "looks secure" never shows while
 * any alert is open at MEDIUM or above; the open-alerts guidance names their count instead. The
 * no-live-scan line never claims where the alerts came from (they may be from deleted live scans).
 */
class DashboardOpenAlertsHonestyTest {

    private fun guidance(scan: RiskLevel?, open: Int, highest: RiskLevel?) =
        DashboardViewModel.guidanceFor(scan, hasCriticalAppRisks = false, hasChains = false,
            openAlertCount = open, highestOpenAlert = highest)

    @Test
    fun `the risk badge is at least the most severe open alert`() {
        assertEquals(RiskLevel.CRITICAL, DashboardViewModel.displayRisk(RiskLevel.MEDIUM, RiskLevel.CRITICAL))
        assertEquals(RiskLevel.HIGH, DashboardViewModel.displayRisk(null, RiskLevel.HIGH))
        assertEquals(RiskLevel.HIGH, DashboardViewModel.displayRisk(RiskLevel.HIGH, RiskLevel.LOW))
        assertEquals(RiskLevel.LOW, DashboardViewModel.displayRisk(RiskLevel.LOW, null))
        assertNull(DashboardViewModel.displayRisk(null, null))
    }

    @Test
    fun `secure-sounding guidance never shows while alerts at MEDIUM or above are open`() {
        for (scan in listOf(RiskLevel.LOW, RiskLevel.MEDIUM, null)) {
            for (highest in listOf(RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)) {
                assertEquals("$scan scan with $highest alerts", Guidance.OPEN_ALERTS, guidance(scan, 3, highest))
            }
        }
        assertEquals("a HIGH scan below CRITICAL alerts", Guidance.OPEN_ALERTS,
            guidance(RiskLevel.HIGH, 1, RiskLevel.CRITICAL))
        // Without open alerts, the scan's own guidance is unchanged.
        assertEquals(Guidance.MEDIUM, guidance(RiskLevel.MEDIUM, 0, null))
        assertEquals(Guidance.LOW, guidance(RiskLevel.LOW, 0, null))
        assertEquals(Guidance.HIGH, guidance(RiskLevel.HIGH, 2, RiskLevel.MEDIUM))
        assertNull(guidance(null, 0, null))
    }

    private val strings = File("src/main/res/values/strings.xml").readText()
    private fun string(name: String) = Regex("<string name=\"$name\"[^>]*>([^<]*)</string>").find(strings)!!.groupValues[1]

    @Test
    fun `the copy is honest - open-alert guidance names the count and the no-scan line claims no source`() {
        assertTrue(string("guidance_medium").contains("mostly secure"))
        val plural = Regex("<plurals name=\"guidance_open_alerts\">([\\s\\S]*?)</plurals>").find(strings)!!.groupValues[1]
        assertTrue("names the count", plural.contains("%1\$d") && plural.contains("%2\$s"))
        assertFalse(plural.contains("secure.") && !plural.contains("before treating"))
        val noScan = string("dashboard_no_live_scan_alerts")
        assertFalse("never claims the alerts come from imports", noScan.contains("import", ignoreCase = true))
        val screen = File("src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt").readText()
        assertTrue(screen.contains("DashboardViewModel.guidanceFor("))
        assertTrue(screen.contains("DashboardViewModel.displayRisk("))
        // guidance_medium / guidance_low render only from their own Guidance branches.
        assertEquals(1, Regex("R\\.string\\.guidance_medium\\b").findAll(screen).count())
        assertTrue(screen.contains("Guidance.MEDIUM -> Triple(stringResource(R.string.guidance_medium)"))
        assertEquals(1, Regex("R\\.string\\.guidance_low\\b").findAll(screen).count())
    }
}
