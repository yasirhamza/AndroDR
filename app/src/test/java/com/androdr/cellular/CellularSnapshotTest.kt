package com.androdr.cellular

import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CellularSnapshotTest {

    private fun sample() = CellularSnapshot(
        mcc = "427", mnc = "01", tac = 4100, ci = 12345L, pci = 77,
        earfcn = 1650, bands = listOf(3), bandwidthKhz = 20000, rat = "LTE",
        operatorAlphaLong = "Ooredoo", operatorAlphaShort = "Ooredoo",
        additionalPlmns = emptyList(), neighborCount = 4, servingRsrp = -95,
        isRegistered = true, capturedAt = 1000L, source = TelemetrySource.LIVE_SCAN,
        previousTac = 4099, previousRat = "LTE", tacChanged = true, ratChanged = false,
        tacChangesLast5m = 2, servingMinusMaxNeighborRsrpDb = 12,
        locationMovedMLast5m = 40,
    )

    @Test
    fun `toFieldMap emits every taxonomy key`() {
        val f = sample().toFieldMap()
        assertEquals("427", f["mcc"])
        assertEquals(4100, f["tac"])
        assertEquals(20000, f["bandwidth_khz"])
        assertEquals("LTE", f["rat"])
        assertEquals("Ooredoo", f["operator_alpha_long"])
        assertEquals(4, f["neighbor_count"])
        assertEquals(true, f["is_registered"])
        assertEquals("LIVE_SCAN", f["source"])
        assertEquals(4099, f["previous_tac"])
        assertEquals(true, f["tac_changed"])
        assertEquals(2, f["tac_changes_last_5m"])
        assertEquals(12, f["serving_minus_max_neighbor_rsrp_db"])
        assertEquals(40, f["location_moved_m_last_5m"])
        assertEquals(24, f.size)
    }

    @Test
    fun `null measurements survive into the field map`() {
        val f = sample().copy(locationMovedMLast5m = null, servingRsrp = null).toFieldMap()
        assertNull(f["location_moved_m_last_5m"])
        assertNull(f["serving_rsrp"])
    }
}
