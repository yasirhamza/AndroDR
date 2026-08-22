package com.androdr.cellular

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.reporting.ReportFormatter
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Proves cellular findings reach the exported report. Without this the export
 * path is an assumption: the section could silently render nothing and the
 * report would look complete while omitting the entire radio plane.
 */
class CellularReportSectionTest {

    private fun scan() = ScanResult(
        timestamp = 1_000L,
        findings = emptyList(),
        bugReportFindings = emptyList(),
        riskySideloadCount = 0,
        knownMalwareCount = 0,
    )

    private fun cellularEvent() = ForensicTimelineEvent(
        startTimestamp = 1_700_000_000_000L,
        source = "cellular_monitor",
        category = "network_anomaly",
        description = "Tracking area churn",
        details = "rat=LTE tac=1437 ci=192816407 pci=167 plmn=427/01 op=Ooredoo " +
            "neighbours=13 rsrp=-84 prevTac=1436 churn5m=4",
        ruleId = "androdr-104",
        attackTechniqueId = "attack.t1430",
    )

    private fun render(events: List<ForensicTimelineEvent>) =
        ReportFormatter.formatScanReport(
            scan = scan(),
            dnsEvents = emptyList(),
            logLines = emptyList(),
            cellularEvents = events,
            versionName = "test",
        )

    @Test
    fun `cellular findings appear in the exported report`() {
        val out = render(listOf(cellularEvent()))
        assertTrue("section header missing", out.contains("CELLULAR (TIER 1)"))
        assertTrue("finding title missing", out.contains("Tracking area churn"))
        assertTrue("rule id missing", out.contains("androdr-104"))
        assertTrue("ATT&CK technique missing", out.contains("attack.t1430"))
    }

    @Test
    fun `the radio CONDITION travels with the finding`() {
        // The condition is the evidence: that the tracking area changed four
        // times is what makes the finding judgeable.
        val out = render(listOf(cellularEvent()))
        assertTrue("radio condition missing", out.contains("churn5m=4"))
        assertTrue("neighbour count missing", out.contains("neighbours=13"))
    }

    @Test
    fun `the exported report never carries tower identity`() {
        // A report is a handoff artifact — it is meant to be copied around, so
        // a tower-level location trail in one is worse than in logcat. The
        // values stay on-device for adjudication; the export gets the
        // condition plus an explicit note that identity was withheld.
        val out = render(listOf(cellularEvent()))
        assertFalse("TAC leaked into the report", out.contains("tac=1437"))
        assertFalse("CI leaked into the report", out.contains("ci=192816407"))
        assertFalse("PCI leaked into the report", out.contains("pci=167"))
        assertFalse("PLMN leaked into the report", out.contains("plmn=427/01"))
        assertFalse("operator leaked into the report", out.contains("op=Ooredoo"))
        assertTrue(
            "the report must say identity was withheld rather than stay silent",
            out.contains("withheld")
        )
    }

    @Test
    fun `no cellular section when there are no findings`() {
        assertFalse(
            "empty section should be omitted entirely",
            render(emptyList()).contains("CELLULAR (TIER 1)")
        )
    }
}
