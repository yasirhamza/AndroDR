package com.androdr.cellular

import com.androdr.data.model.CaptureContext
import com.androdr.data.model.CaptureOrigin
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.NeighborDetail
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ServingSignal
import com.androdr.data.model.SimContext
import com.androdr.data.model.TelemetrySource
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

    private fun snapshot() = CellularSnapshot(
        mcc = "427", mnc = "01", tac = 1437, ci = 192816407L, pci = 167,
        earfcn = 1600, bands = listOf(3), bandwidthKhz = null, rat = "LTE",
        operatorAlphaLong = "Ooredoo", operatorAlphaShort = "Ooredoo",
        additionalPlmns = emptyList(), neighborCount = 13, servingRsrp = -84,
        isRegistered = true, capturedAt = 1000L, source = TelemetrySource.LIVE_SCAN,
        previousTac = 1436, previousRat = "LTE", tacChanged = true, ratChanged = false,
        tacChangesLast5m = 4, servingMinusMaxNeighborRsrpDb = 8,
        locationMovedMLast5m = null,
    )

    private fun renderTelemetry(s: CellularSnapshot?, deliveries: Int) =
        ReportFormatter.formatScanReport(
            scan = scan(),
            dnsEvents = emptyList(),
            logLines = emptyList(),
            cellularSnapshot = s,
            cellularDeliveries = deliveries,
            versionName = "test",
        )

    @Test
    fun `radio telemetry is reported even with no findings`() {
        // A report showing only anomalies cannot distinguish "the radio was
        // clean" from "the monitor never ran" — and cell info comes back EMPTY
        // rather than erroring when not permitted, so that difference is real.
        val out = renderTelemetry(snapshot(), deliveries = 12)
        assertTrue("telemetry section missing", out.contains("CELLULAR TELEMETRY (TIER 1)"))
        assertTrue("delivery count missing", out.contains("12"))
        assertTrue("technology missing", out.contains("LTE"))
        assertTrue("neighbour count missing", out.contains("13"))
        assertTrue("churn count missing", out.contains("TAC changes (5m): 4"))
    }

    @Test
    fun `telemetry section never carries tower identity`() {
        val out = renderTelemetry(snapshot(), deliveries = 12)
        assertFalse("TAC leaked", out.contains("1437"))
        assertFalse("CI leaked", out.contains("192816407"))
        assertFalse("PCI leaked", out.contains("PCI 167"))
        assertTrue("must state what was withheld", out.contains("withheld"))
    }

    /** Populated context: the SIM record and the circumstances of the read. */
    private fun contextual() = snapshot().copy(
        locationMovedMLast5m = 640,
        locationFixAgeS = 12,
        capture = CaptureContext(
            origin = CaptureOrigin.PRIME, appForeground = false, screenInteractive = false,
            dataActivity = "NONE", rawRecordCount = 14,
        ),
        sim = SimContext(
            mcc = "427", mnc = "01", operatorName = "Ooredoo",
            plmnMatchesSim = true, operatorNameMatchesSim = false,
        ),
    )

    @Test
    fun `the circumstances of the read and the SIM agreement are reported`() {
        val out = renderTelemetry(contextual(), deliveries = 12)
        assertTrue(out.contains("moved (5m)      : 640 m (fix 12s old)"))
        assertTrue(out.contains("screen on       : false"))
        assertTrue(out.contains("records in read : 14"))
        assertTrue(out.contains("PLMN = SIM      : true"))
        assertTrue(out.contains("name = SIM      : false"))

        val rows = renderHistory(listOf(contextual()))
        listOf(
            "moved5m=640", "fixAge=12", "origin=PRIME", "records=14", "screen=false",
            "simPlmn=true", "simName=false",
        ).forEach { assertTrue("observation row missing $it", rows.contains(it)) }
    }

    /** Signal quality and a neighbour list with a PCI clash and two channels. */
    private fun measured() = snapshot().copy(
        signal = ServingSignal(rsrq = -11, sinr = 10, cqi = null, timingAdvance = 4, dbm = -84),
        neighbors = NeighborDetail(
            pcis = listOf(12, 167), earfcns = listOf(1600, 1850), rsrps = listOf(-95, -101),
            rats = listOf("LTE", "LTE"), maxRsrp = -95, servingPciInNeighbors = true, distinctEarfcnCount = 2,
        ),
    )

    @Test
    fun `signal quality and the neighbour scalars are reported`() {
        val out = renderTelemetry(measured(), deliveries = 1)
        assertTrue(out.contains("serving RSRQ    : -11 dB"))
        assertTrue(out.contains("serving SINR    : 10 dB"))
        assertTrue("timing advance must carry its rough distance", out.contains("timing advance  : 4 (~312 m)"))
        assertTrue(out.contains("strongest nbr   : -95 dBm"))
        assertTrue(out.contains("nbr channels    : 2"))
        assertTrue(out.contains("PCI in nbrs     : true"))

        val rows = renderHistory(listOf(measured()))
        listOf("rsrq=-11", "sinr=10", "cqi=-", "ta=4", "dbm=-84", "nMaxRsrp=-95", "nEarfcns=2", "pciInN=true")
            .forEach { assertTrue("observation row missing $it", rows.contains(it)) }
    }

    @Test
    fun `an unmeasured radio says so rather than inventing a value`() {
        val out = renderTelemetry(snapshot(), deliveries = 1)
        assertTrue(out.contains("timing advance  : not reported"))
        assertTrue(out.contains("strongest nbr   : not reported"))
        assertTrue(out.contains("PCI in nbrs     : unknown"))
    }

    @Test
    fun `the neighbours' identities never reach the report`() {
        // Each neighbour's PCI and channel is a tower identifier like the
        // serving cell's; only the scalars derived from the list are exported.
        val out = renderTelemetry(measured(), deliveries = 1) + renderHistory(listOf(measured()))
        assertFalse("neighbour PCI list leaked", out.contains("12, 167") || out.contains("12,167"))
        assertFalse("neighbour channel list leaked", out.contains("1600, 1850") || out.contains("1600,1850"))
        assertFalse("neighbour RSRP list leaked", out.contains("-95, -101") || out.contains("-95,-101"))
    }

    @Test
    fun `the SIM's own identity never reaches the report`() {
        // The comparison result is exportable; what the SIM says about the
        // subscriber's home operator is not.
        val sim = SimContext(mcc = "262", mnc = "07", operatorName = "Telekom-Testnetz")
        val out = renderTelemetry(snapshot().copy(sim = sim), deliveries = 1) +
            renderHistory(listOf(snapshot().copy(sim = sim)))
        assertFalse("SIM MCC leaked", out.contains("262"))
        assertFalse("SIM name leaked", out.contains("Telekom-Testnetz"))
    }

    private fun renderHistory(history: List<CellularSnapshot>) =
        ReportFormatter.formatScanReport(
            scan = scan(),
            dnsEvents = emptyList(),
            logLines = emptyList(),
            cellularSnapshot = history.firstOrNull(),
            cellularDeliveries = history.size,
            cellularHistory = history,
            versionName = "test",
        )

    /**
     * The monitor retained 46 observations while the report printed one — the
     * export read `latest` and never `history`. The time series IS the Tier 1
     * evidence, so every retained observation must reach the report.
     */
    @Test
    fun `every retained observation reaches the report, oldest first`() {
        // history is newest-first, as CellularState keeps it.
        val history = listOf(
            snapshot().copy(capturedAt = 3_000L, neighborCount = 6),
            snapshot().copy(capturedAt = 2_000L, neighborCount = 0),
            snapshot().copy(capturedAt = 1_000L, neighborCount = 13),
        )
        val out = renderHistory(history)
        assertTrue("observation count missing", out.contains("Observations this session, oldest first: 3"))
        val first = out.indexOf("neighbours=13")
        val second = out.indexOf("neighbours=0 ")
        val third = out.indexOf("neighbours=6")
        assertTrue("all three observations must be present", first >= 0 && second >= 0 && third >= 0)
        assertTrue("observations must be rendered oldest first", first < second && second < third)
    }

    @Test
    fun `observation rows never carry tower identity`() {
        val out = renderHistory(listOf(snapshot(), snapshot().copy(capturedAt = 2_000L)))
        assertFalse("TAC leaked in an observation row", out.contains("1437"))
        assertFalse("CI leaked in an observation row", out.contains("192816407"))
        assertFalse("PCI leaked in an observation row", out.contains("167"))
        assertFalse("PLMN leaked in an observation row", out.contains("427"))
        assertFalse("operator leaked in an observation row", out.contains("Ooredoo"))
    }

    @Test
    fun `the report says when the retained window is full`() {
        val full = (1..CellularState.MAX_HISTORY).map { snapshot().copy(capturedAt = it * 1_000L) }
        assertTrue(
            "a full history must say it is bounded, or 100 rows read as the whole session",
            renderHistory(full).contains("most recent ${CellularState.MAX_HISTORY} retained"),
        )
        assertFalse(
            "a partial history must not claim to be bounded",
            renderHistory(full.take(5)).contains("retained)"),
        )
    }

    @Test
    fun `the report accounts for deliveries that were not recorded`() {
        // 46 delivered but 44 rows would read as two lost observations
        // unless the report says they were repeats.
        val out = ReportFormatter.formatScanReport(
            scan = scan(),
            dnsEvents = emptyList(),
            logLines = emptyList(),
            cellularSnapshot = snapshot(),
            cellularDeliveries = 46,
            cellularDuplicates = 2,
            versionName = "test",
        )
        assertTrue(out.contains("delivered this session: 46"))
        assertTrue(out.contains("2 duplicate deliveries not recorded; 44 distinct"))
        assertFalse(
            "no duplicates means no caveat",
            renderTelemetry(snapshot(), deliveries = 12).contains("duplicate"),
        )
    }

    @Test
    fun `telemetry section says so when the monitor produced nothing`() {
        val out = renderTelemetry(null, deliveries = 0)
        assertTrue(out.contains("No radio telemetry captured"))
        assertTrue(
            "must distinguish 'not running' from 'clean radio'",
            out.contains("not running") || out.contains("no serving cell")
        )
    }
}
