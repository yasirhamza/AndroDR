package com.androdr.cellular

import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every monitor session start produced the same observation twice — prime
 * plus the registration callback — and, when a rule matched, two identical
 * findings in the same second. This pins the filter that collapses them.
 */
class DuplicateDeliveryFilterTest {

    private fun snapshot(at: Long) = CellularSnapshot(
        mcc = "427", mnc = "01", tac = 1437, ci = 192816407L, pci = 167,
        earfcn = 1600, bands = listOf(3), bandwidthKhz = null, rat = "LTE",
        operatorAlphaLong = "Ooredoo", operatorAlphaShort = "Ooredoo",
        additionalPlmns = emptyList(), neighborCount = 13, servingRsrp = -84,
        isRegistered = true, capturedAt = at, source = TelemetrySource.LIVE_SCAN,
        previousTac = null, previousRat = null, tacChanged = false, ratChanged = false,
        tacChangesLast5m = 0, servingMinusMaxNeighborRsrpDb = 8,
        locationMovedMLast5m = null,
    )

    @Test
    fun `the same facts delivered again within the window are a duplicate`() {
        val filter = DuplicateDeliveryFilter(windowMillis = 2_000L)
        assertFalse("first delivery is always new", filter.isDuplicate(snapshot(at = 1_000L)))
        assertTrue(filter.isDuplicate(snapshot(at = 1_400L)))
    }

    @Test
    fun `the same facts after the window are a new observation`() {
        // A stationary radio reporting the same cell later IS evidence: that
        // nothing changed. Only the near-simultaneous repeat is noise.
        val filter = DuplicateDeliveryFilter(windowMillis = 2_000L)
        filter.isDuplicate(snapshot(at = 1_000L))
        assertFalse(filter.isDuplicate(snapshot(at = 3_001L)))
    }

    @Test
    fun `a change in any raw fact is never a duplicate`() {
        val filter = DuplicateDeliveryFilter(windowMillis = 2_000L)
        filter.isDuplicate(snapshot(at = 1_000L))
        assertFalse(
            "neighbour count changed — that is a new observation even one ms later",
            filter.isDuplicate(snapshot(at = 1_001L).copy(neighborCount = 0)),
        )
    }

    @Test
    fun `derived and clock fields do not make a repeat look new`() {
        // The second delivery is stamped later and the store may report
        // different previous_* values; none of that is a radio fact.
        val filter = DuplicateDeliveryFilter(windowMillis = 2_000L)
        filter.isDuplicate(snapshot(at = 1_000L))
        val repeat = snapshot(at = 1_500L).copy(
            previousTac = 1437, previousRat = "LTE", tacChangesLast5m = 1, locationMovedMLast5m = 3,
        )
        assertTrue(filter.isDuplicate(repeat))
    }

    @Test
    fun `the window is measured from the last accepted observation, not the last duplicate`() {
        // Otherwise a radio that re-reports every 1.5 s could be suppressed
        // forever, and the history would go silent while the monitor is alive.
        val filter = DuplicateDeliveryFilter(windowMillis = 2_000L)
        filter.isDuplicate(snapshot(at = 0L))
        assertTrue(filter.isDuplicate(snapshot(at = 1_500L)))
        assertFalse(filter.isDuplicate(snapshot(at = 3_000L)))
    }

    @Test
    fun `every excluded key is a real field-map key`() {
        // A renamed field would otherwise silently stop being excluded and
        // every repeat would look new again.
        val keys = snapshot(at = 0L).toFieldMap().keys
        val unknown = CellularSnapshot.NON_OBSERVATION_KEYS - keys
        assertTrue("NON_OBSERVATION_KEYS names keys that toFieldMap() does not emit: $unknown", unknown.isEmpty())
    }
}
