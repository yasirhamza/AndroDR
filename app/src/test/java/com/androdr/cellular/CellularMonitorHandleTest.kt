package com.androdr.cellular

import android.content.Context
import android.telephony.CellInfo
import com.androdr.data.model.CaptureOrigin
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.repo.ScanRepository
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CoroutineScope
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
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

    private fun monitor() = CellularMonitor(
        context = mockk<Context>(relaxed = true),
        engine = engine,
        repository = repository,
        scope = CoroutineScope(Dispatchers.Unconfined),
        clock = { now },
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
    fun `the same radio re-reported after the window is a new observation`() {
        val m = monitor()
        m.handle(lteCell(), CaptureOrigin.PRIME)
        now += DuplicateDeliveryFilter.DEFAULT_WINDOW_MILLIS + 1
        m.handle(lteCell(), CaptureOrigin.CALLBACK)

        assertEquals(2, CellularState.history.value.size)
        assertEquals(0, CellularState.duplicates.value)
    }
}
