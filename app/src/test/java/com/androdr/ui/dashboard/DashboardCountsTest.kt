package com.androdr.ui.dashboard

import com.androdr.data.model.RiskLevel
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanWithFindings
import com.androdr.data.repo.CurrentFindingsSummary
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Every Dashboard count comes from one set (spec §5.4). On a SM-F916B with six detections of one
 * malicious domain, the risk line read "6 app risk(s) · 4 device flag(s)" while the alerts card read
 * "Current findings: 5 (4 from the latest scan, 1 open alert)": the risk line counted the scan's raw
 * findings, so each DNS detection became an "app risk", and the guidance said to remove apps. On
 * another phone it read "1 device flag(s)" beside "2 from the latest scan": the alerts card counted an
 * informational finding the risk line dropped. Informational findings count nowhere.
 */
class DashboardCountsTest {

    private fun f(level: String, category: FindingCategory, rule: String = "r") =
        Finding(ruleId = rule, title = rule, level = level, category = category)

    private fun scan(findings: List<Finding>) = ScanWithFindings(
        ScanResult(id = 1L, timestamp = 1L, bugReportFindings = emptyList(), riskySideloadCount = 0,
            knownMalwareCount = 0),
        findings,
    )

    private val posture = List(4) { f("medium", FindingCategory.DEVICE_POSTURE, "androdr-04$it") }
    private val dnsDetections = List(6) { f("critical", FindingCategory.APP_RISK, "androdr-003") }

    /** The parts always add up to the total, whatever the inputs. */
    private fun assertAddsUp(c: DashboardCounts) {
        assertEquals(c.stateFindings.size, c.appRisks + c.deviceFlags + c.warningSigns)
        assertEquals(c.total, c.stateFindings.size + c.openAlertCount)
    }

    @Test
    fun `DNS detections are open alerts, not app risks`() {
        val current = CurrentFindingsSummary(posture, openAlertCount = 1, highestOpenAlertLevel = RiskLevel.CRITICAL)
        val c = DashboardCounts.of(scan(posture + dnsDetections), unsaved = false, current = current)
        assertEquals(0, c.appRisks)
        assertEquals(4, c.deviceFlags)
        assertEquals(5, c.total)
        assertAddsUp(c)
        assertEquals("the scan's own risk comes from its state findings", RiskLevel.MEDIUM, c.scanRisk)
        assertFalse("never 'remove apps' for a domain lookup", c.hasCriticalAppRisks)
        assertEquals(Guidance.OPEN_ALERTS, DashboardViewModel.guidanceFor(c.scanRisk, c.hasCriticalAppRisks,
            c.hasChains, c.openAlertCount, current.highestOpenAlertLevel))
    }

    @Test
    fun `informational findings count nowhere`() {
        val state = listOf(f("medium", FindingCategory.DEVICE_POSTURE), f("informational", FindingCategory.APP_RISK))
        val c = DashboardCounts.of(scan(state), unsaved = false, current = CurrentFindingsSummary(state, 6))
        assertEquals(1, c.deviceFlags)
        assertEquals(0, c.appRisks)
        assertEquals("'from the latest scan' matches the risk line", 1, c.stateFindings.size)
        assertEquals(7, c.total)
        assertAddsUp(c)
    }

    @Test
    fun `an unsaved scan answers with its own findings, not an older saved scan's`() {
        val older = CurrentFindingsSummary(posture, 0)
        val unsaved = listOf(f("critical", FindingCategory.APP_RISK), f("high", FindingCategory.CORRELATION))
        val c = DashboardCounts.of(scan(unsaved), unsaved = true, current = older)
        assertEquals(1, c.appRisks)
        assertEquals(0, c.deviceFlags)
        assertEquals(1, c.warningSigns)
        assertEquals(RiskLevel.CRITICAL, c.scanRisk)
        assertAddsUp(c)
    }

    @Test
    fun `no scan has no scan risk, only alerts`() {
        val c = DashboardCounts.of(null, unsaved = false, current = CurrentFindingsSummary(emptyList(), 2))
        assertNull(c.scanRisk)
        assertEquals(2, c.total)
        assertAddsUp(c)
    }

    /**
     * The screens read [DashboardCounts] only: a raw read of the scan's findings is how the risk line
     * came to count DNS detections as app risks while the alerts card did not.
     */
    @Test
    fun `the Dashboard reads its counts from DashboardCounts only`() {
        val raw = Regex(
            """(?<!counts)\.(appRisks|deviceFlags|activityChains|overallRiskLevel)\b|""" +
                """(?<!counts\.)stateFindings\.size|current\.count\b"""
        )
        for (name in listOf("DashboardScreen.kt", "OpenAlertsCard.kt")) {
            val src = File("src/main/java/com/androdr/ui/dashboard/$name").readText()
            val hits = raw.findAll(src).map { it.value }.toList()
            assertTrue("$name reads raw finding counts: $hits", hits.isEmpty())
        }
    }

    @Test
    fun `untriggered findings are not counted`() {
        val state = listOf(f("high", FindingCategory.APP_RISK).copy(triggered = false))
        val c = DashboardCounts.of(scan(state), unsaved = true, current = CurrentFindingsSummary.EMPTY)
        assertEquals(0, c.total)
        assertEquals(RiskLevel.LOW, c.scanRisk)
    }
}
