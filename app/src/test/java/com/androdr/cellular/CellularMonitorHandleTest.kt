package com.androdr.cellular

import android.content.Context
import android.telephony.CellInfo
import com.androdr.data.model.CaptureContext
import com.androdr.data.model.CaptureOrigin
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ServiceContext
import com.androdr.data.repo.ScanRepository
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CoroutineScope
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * `handle()` end to end on a mocked cell list: the platform hands over the
 * same list twice at session start (prime, then the registration callback),
 * and that must yield ONE observation and ONE finding, not two of each.
 *
 * The report that motivated this showed every session-start finding twice,
 * one second apart — the same evidence counted twice.
 */
class CellularMonitorHandleTest {

    private val engine = mockk<SigmaRuleEngine>()
    private val repository = mockk<ScanRepository>()
    private var now = 1_000L
    private var screenInteractive: Boolean? = true
    private var movement = Movement()
    private var sim: SimIdentity? = SimIdentity(mcc = "427", mnc = "01", operatorName = "Ooredoo")
    private var service = ServiceContext(state = "IN_SERVICE", isRoaming = false, dataNetworkType = "LTE")

    /** Circumstances under the test's control; no platform reads. */
    private val deviceContext = object : DeviceContextSource {
        override fun capture(origin: CaptureOrigin, rawRecordCount: Int) = CaptureContext(
            origin = origin,
            appForeground = false,
            screenInteractive = screenInteractive,
            dataActivity = "NONE",
            rawRecordCount = rawRecordCount,
        )

        override fun movement(now: Long) = movement

        override fun sim() = sim

        override fun service() = service
    }

    private fun monitor() = CellularMonitor(
        context = mockk<Context>(relaxed = true),
        engine = engine,
        repository = repository,
        scope = CoroutineScope(Dispatchers.Unconfined),
        clock = { now },
        deviceContext = deviceContext,
    )

    private fun lteCell(neighbours: Int = 13): List<CellInfo> = CellInfoFixtures.lteList(neighbours)

    private fun finding() = Finding(ruleId = "androdr-102", title = "Serving cell has no neighbours", level = "low")

    @Before
    fun setUp() {
        CellularState.reset()
        every { engine.evaluateCellular(any()) } returns listOf(finding())
        coEvery { repository.logCellularTimelineEvents(any()) } just Runs
    }

    @After
    fun tearDown() = CellularState.reset()

    @Test
    fun `prime followed by the registration callback records one observation`() {
        val m = monitor()
        m.handle(lteCell(), CaptureOrigin.PRIME)
        now += 300
        m.handle(lteCell(), CaptureOrigin.CALLBACK)

        assertEquals("one physical observation, one history row", 1, CellularState.history.value.size)
        assertEquals("both deliveries still count — the monitor was alive", 2, CellularState.deliveries.value)
        assertEquals(1, CellularState.duplicates.value)
    }

    @Test
    fun `the duplicate is neither evaluated nor persisted`() {
        val m = monitor()
        m.handle(lteCell(), CaptureOrigin.PRIME)
        now += 300
        m.handle(lteCell(), CaptureOrigin.CALLBACK)

        verify(exactly = 1) { engine.evaluateCellular(any<List<CellularSnapshot>>()) }
        coVerify(exactly = 1) { repository.logCellularTimelineEvents(any()) }
        assertEquals("one finding, not the same one twice", 1, CellularState.triggered.value.size)
    }

    @Test
    fun `a changed radio within the window is a new observation`() {
        val m = monitor()
        m.handle(lteCell(neighbours = 13), CaptureOrigin.PRIME)
        now += 300
        m.handle(lteCell(neighbours = 0), CaptureOrigin.CALLBACK)

        assertEquals(2, CellularState.history.value.size)
        assertEquals(0, CellularState.duplicates.value)
        verify(exactly = 2) { engine.evaluateCellular(any<List<CellularSnapshot>>()) }
    }

    @Test
    fun `an NR serving cell produces a snapshot with a cell in it`() {
        // The LTE-only reader left every identity field null on NR while
        // rat said "NR" — a downgrade finding would have had no cell to judge.
        val m = monitor()
        m.handle(listOf(CellInfoFixtures.nr()) + CellInfoFixtures.lteList(neighbours = 2).drop(1), CaptureOrigin.PRIME)

        val s = CellularState.latest.value
        assertNotNull(s)
        assertEquals("NR", s!!.rat)
        assertEquals(1437, s.tac)
        assertEquals(3_456_789_012L, s.ci)
        assertEquals(640_000, s.earfcn)
        assertEquals(-90, s.servingRsrp)
        assertEquals("neighbour RSRP is read across technologies", -90 - (-95), s.servingMinusMaxNeighborRsrpDb)
        assertEquals(2, s.neighborCount)
    }

    @Test
    fun `the circumstances of the read reach the snapshot`() {
        // Six "no neighbours" findings in the 0.9.0.638 report could not be
        // told from an idle radio: nothing recorded whether the screen was on
        // or how many records the platform handed over.
        val m = monitor()
        screenInteractive = false
        m.handle(lteCell(neighbours = 0), CaptureOrigin.PRIME)

        val c = CellularState.latest.value!!.capture
        assertEquals(CaptureOrigin.PRIME, c.origin)
        assertEquals(false, c.screenInteractive)
        assertEquals(false, c.appForeground)
        assertEquals("NONE", c.dataActivity)
        assertEquals("serving cell only", 1, c.rawRecordCount)
    }

    @Test
    fun `movement and fix age reach the snapshot`() {
        // location_moved_m_last_5m was hard-coded null, so androdr-104's
        // "while stationary" could never be applied.
        val m = monitor()
        movement = Movement(movedMetersLast5m = 640, fixAgeSeconds = 12)
        m.handle(lteCell(), CaptureOrigin.PRIME)

        val s = CellularState.latest.value!!
        assertEquals(640, s.locationMovedMLast5m)
        assertEquals(12, s.locationFixAgeS)
    }

    @Test
    fun `the serving cell is compared against the SIM`() {
        // The fixtures broadcast 427/01 "Ooredoo", the same as the SIM.
        val m = monitor()
        m.handle(lteCell(), CaptureOrigin.PRIME)
        val s = CellularState.latest.value!!.sim
        assertEquals(true, s.plmnMatchesSim)
        assertEquals(true, s.operatorNameMatchesSim)
        assertEquals("427", s.mcc)
    }

    @Test
    fun `a different SIM mismatches and no SIM compares to nothing`() {
        sim = SimIdentity(mcc = "427", mnc = "02", operatorName = "Vodafone")
        monitor().handle(lteCell(), CaptureOrigin.PRIME)
        assertEquals(false, CellularState.latest.value!!.sim.plmnMatchesSim)
        assertEquals(false, CellularState.latest.value!!.sim.operatorNameMatchesSim)

        sim = null
        // A fresh monitor: the duplicate filter is per instance, so no window to wait out.
        monitor().handle(lteCell(), CaptureOrigin.PRIME)
        assertNull(CellularState.latest.value!!.sim.plmnMatchesSim)
    }

    @Test
    fun `signal quality and the neighbour list reach the snapshot`() {
        // The 0.9.0.638 report carried RSRP and a neighbour COUNT and nothing
        // else about the radio's quality or who the neighbours were.
        val m = monitor()
        val serving = CellInfoFixtures.lte(pci = 167, earfcn = 1600, rsrq = -9, rssnr = 12, timingAdvance = 4)
        val neighbours = listOf(
            CellInfoFixtures.lte(registered = false, pci = 12, earfcn = 1600, rsrp = -95),
            CellInfoFixtures.lte(registered = false, pci = 167, earfcn = 1850, rsrp = -101),
            CellInfoFixtures.lte(registered = false, pci = 167, earfcn = 1600, rsrp = -97),
        )
        m.handle(listOf(serving) + neighbours, CaptureOrigin.PRIME)

        val s = CellularState.latest.value!!
        assertEquals(-9, s.signal.rsrq)
        assertEquals(12, s.signal.sinr)
        assertEquals(4, s.signal.timingAdvance)
        assertEquals(-84, s.signal.dbm)
        assertEquals(listOf(12, 167, 167), s.neighbors.pcis)
        assertEquals(listOf(1600, 1850, 1600), s.neighbors.earfcns)
        assertEquals(listOf(-95, -101, -97), s.neighbors.rsrps)
        assertEquals(-95, s.neighbors.maxRsrp)
        assertEquals(2, s.neighbors.distinctEarfcnCount)
        assertEquals(
            "a neighbour on the serving channel repeats the serving PCI",
            true, s.neighbors.servingPciInNeighbors,
        )
        assertEquals("the margin is derived from the same list", -84 - (-95), s.servingMinusMaxNeighborRsrpDb)
        assertEquals(3, s.neighborCount)
    }

    @Test
    fun `a network-chosen operator name cannot forge a pair in the persisted row`() {
        // The operator name is the one free-text string in a cell record.
        // A fake cell that broadcasts "Evil rsrp=-1\nsvc=FORGED" must not
        // end up with a second rsrp= in the timeline row or a second line
        // in the CSV that is exported from it.
        val persisted = slot<List<ForensicTimelineEvent>>()
        coEvery { repository.logCellularTimelineEvents(capture(persisted)) } just Runs
        val serving = CellInfoFixtures.lte(operatorName = "Evil rsrp=-1\nsvc=FORGED")
        monitor().handle(listOf(serving), CaptureOrigin.PRIME)

        val details = persisted.captured.single().details.orEmpty()
        assertFalse("a line break reached the timeline row", details.contains('\n'))
        assertEquals("exactly one rsrp pair", 1, Regex("(^| )rsrp=").findAll(details).count())
        assertFalse("a forged pair reached the timeline row", details.contains(" svc=FORGED"))
        assertTrue("the name itself is kept, folded", details.contains("op=Evil_rsrp=-1_svc=FORGED"))
    }

    @Test
    fun `a finding title that names the tower is not persisted as the description`() {
        // The description is exported unredacted. A remote rule whose
        // triggeredTitle interpolates {tac} or {ci} would put the tower into
        // a shared report; the monitor falls back to the rule's static title,
        // and to a bare label when it has no rule to ask.
        val persisted = slot<List<ForensicTimelineEvent>>()
        coEvery { repository.logCellularTimelineEvents(capture(persisted)) } just Runs
        every { engine.evaluateCellular(any()) } returns listOf(
            Finding(ruleId = "androdr-999", title = "Cell 192816407 in TAC 1437 vanished", level = "low"),
        )
        every { engine.getRules() } returns emptyList()
        monitor().handle(lteCell(), CaptureOrigin.PRIME)

        val description = persisted.captured.single().description
        assertFalse("CI in the exported description", description.contains("192816407"))
        assertFalse("TAC in the exported description", description.contains("1437"))
        assertEquals("Cellular finding androdr-999", description)
    }

    @Test
    fun `a finding title without identity is persisted as it is`() {
        val persisted = slot<List<ForensicTimelineEvent>>()
        coEvery { repository.logCellularTimelineEvents(capture(persisted)) } just Runs
        monitor().handle(lteCell(), CaptureOrigin.PRIME)
        assertEquals("Serving cell has no neighbours", persisted.captured.single().description)
    }

    @Test
    fun `a delivery with no registered cell is an observation, not a dropped one`() {
        // The radio sees towers and is camped on none — the state a fake
        // cell forcing a detach leaves the phone in. It used to be dropped
        // here, leaving a gap in the timeline where the evidence was.
        every { engine.evaluateCellular(any()) } returns emptyList()
        val m = monitor()
        m.handle(lteCell(), CaptureOrigin.PRIME)
        now += 5_000
        service = ServiceContext(state = "OUT_OF_SERVICE", isRoaming = false, dataNetworkType = "UNKNOWN")
        m.handle(CellInfoFixtures.lteList(neighbours = 3).drop(1), CaptureOrigin.CALLBACK)

        assertEquals(2, CellularState.history.value.size)
        val s = CellularState.latest.value!!
        assertEquals(false, s.isRegistered)
        assertEquals("UNKNOWN", s.rat)
        assertNull(s.tac)
        assertNull(s.ci)
        assertNull(s.servingRsrp)
        assertEquals("the neighbours the radio can see are still counted", 3, s.neighborCount)
        assertEquals("the registration side is what makes this judgeable", "OUT_OF_SERVICE", s.service.state)
        assertEquals("the last registered TAC is still the previous one", 1437, s.previousTac)
        assertFalse("losing the cell is not a tracking-area change", s.tacChanged)
        assertEquals(0, s.tacChangesLast5m)
        verify(exactly = 2) { engine.evaluateCellular(any<List<CellularSnapshot>>()) }
    }

    @Test
    fun `an unregistered read does not make the next registered one look like a change`() {
        every { engine.evaluateCellular(any()) } returns emptyList()
        val m = monitor()
        m.handle(lteCell(), CaptureOrigin.PRIME)
        now += 5_000
        m.handle(CellInfoFixtures.lteList(neighbours = 3).drop(1), CaptureOrigin.CALLBACK)
        now += 5_000
        m.handle(lteCell(), CaptureOrigin.CALLBACK)

        val s = CellularState.latest.value!!
        assertEquals(true, s.isRegistered)
        assertFalse("back on the same cell: no change", s.tacChanged)
        assertFalse(s.ratChanged)
        assertEquals(0, s.tacChangesLast5m)
    }

    @Test
    fun `an empty delivery is logged and nothing else`() {
        val m = monitor()
        m.handle(emptyList(), CaptureOrigin.CALLBACK)
        assertEquals(0, CellularState.history.value.size)
        verify(exactly = 0) { engine.evaluateCellular(any<List<CellularSnapshot>>()) }
    }

    @Test
    fun `the registration state reaches the snapshot and a change of it is a new observation`() {
        val m = monitor()
        m.handle(lteCell(), CaptureOrigin.PRIME)
        assertEquals("IN_SERVICE", CellularState.latest.value!!.service.state)
        assertEquals(false, CellularState.latest.value!!.service.isRoaming)
        assertEquals("LTE", CellularState.latest.value!!.service.dataNetworkType)

        // Roaming is a fact about the radio, not the read: the same cell
        // list seen while roaming is a different observation.
        now += 300
        service = service.copy(isRoaming = true)
        m.handle(lteCell(), CaptureOrigin.CALLBACK)
        assertEquals(2, CellularState.history.value.size)
        assertEquals(true, CellularState.latest.value!!.service.isRoaming)
    }

    @Test
    fun `a change of circumstances alone is still the same observation`() {
        val m = monitor()
        screenInteractive = true
        m.handle(lteCell(), CaptureOrigin.PRIME)
        now += 300
        screenInteractive = false
        m.handle(lteCell(), CaptureOrigin.CALLBACK)

        assertEquals("the radio did not change; the screen did", 1, CellularState.history.value.size)
        assertEquals(1, CellularState.duplicates.value)
    }

    @Test
    fun `the same radio re-reported after the window is a new observation`() {
        val m = monitor()
        m.handle(lteCell(), CaptureOrigin.PRIME)
        now += DuplicateDeliveryFilter.DEFAULT_WINDOW_MILLIS + 1
        m.handle(lteCell(), CaptureOrigin.CALLBACK)

        assertEquals(2, CellularState.history.value.size)
        assertEquals(0, CellularState.duplicates.value)
    }
}
