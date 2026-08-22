package com.androdr.cellular

import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.TelemetrySource
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * Stopping collection must not discard what was already observed.
 *
 * The monitor used to wipe latest/history/findings when it stopped, so
 * toggling the VPN erased a session's worth of real observations. A report
 * exported afterwards then said "No radio telemetry captured this session"
 * while the same data had been on screen moments before — the report was
 * honest, the state had been destroyed underneath it.
 */
class CellularStateLifecycleTest {

    private fun snapshot(at: Long) = CellularSnapshot(
        mcc = "427", mnc = "02", tac = 171, ci = 3046670L, pci = 45,
        earfcn = 425, bands = listOf(1), bandwidthKhz = null, rat = "LTE",
        operatorAlphaLong = "Vodafone Qatar", operatorAlphaShort = "Vodafone Qatar",
        additionalPlmns = emptyList(), neighborCount = 11, servingRsrp = -77,
        isRegistered = true, capturedAt = at, source = TelemetrySource.LIVE_SCAN,
        previousTac = null, previousRat = null, tacChanged = false, ratChanged = false,
        tacChangesLast5m = 0, servingMinusMaxNeighborRsrpDb = null,
        locationMovedMLast5m = null,
    )

    @Before fun setUp() = CellularState.reset()
    @After fun tearDown() = CellularState.reset()

    @Test
    fun `stopping keeps the observations and only changes status`() {
        CellularState.record(snapshot(1_000L), emptyList())
        CellularState.markStopped()

        assertNotNull(
            "the last observation must survive a stop — the report reads this",
            CellularState.latest.value,
        )
        assertEquals("history must survive a stop", 1, CellularState.history.value.size)
        assertEquals("the delivery count must survive a stop", 1, CellularState.deliveries.value)
        assertEquals(
            "status must reflect that collection stopped",
            CellularState.Status.NOT_STARTED, CellularState.status.value,
        )
    }

    @Test
    fun `recording after a stop resumes without losing prior observations`() {
        CellularState.record(snapshot(1_000L), emptyList())
        CellularState.markStopped()
        CellularState.record(snapshot(2_000L), emptyList())

        assertEquals(2, CellularState.history.value.size)
        assertEquals(2, CellularState.deliveries.value)
        assertEquals(CellularState.Status.ACTIVE, CellularState.status.value)
        assertEquals(
            "newest first",
            2_000L, CellularState.history.value.first().capturedAt,
        )
    }

    @Test
    fun `reset really does clear everything`() {
        CellularState.record(snapshot(1_000L), emptyList())
        CellularState.reset()
        assertNull(CellularState.latest.value)
        assertEquals(0, CellularState.history.value.size)
        assertEquals(0, CellularState.deliveries.value)
    }
}
