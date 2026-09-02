package com.androdr.cellular

import com.androdr.data.model.CaptureContext
import com.androdr.data.model.CaptureOrigin
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.NeighborDetail
import com.androdr.data.model.ServiceContext
import com.androdr.data.model.ServingSignal
import com.androdr.data.model.SimContext
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CellularSnapshotTest {

    /** 24 v1 keys + location_fix_age_s + 6 signal + 7 neighbour + 5 capture + 5 SIM + 3 service. */
    private val expectedKeys = 51

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
        assertEquals(expectedKeys, f.size)
    }

    @Test
    fun `grouped fields merge flat without a key colliding`() {
        // Five sub-maps are merged with `+`; a duplicate key would silently
        // drop one emitter's value under the other's name.
        val s = sample()
        val parts = listOf(
            s.signal.toFieldMap(), s.neighbors.toFieldMap(), s.capture.toFieldMap(),
            s.sim.toFieldMap(), s.service.toFieldMap(),
        )
        val merged = s.toFieldMap()
        assertEquals(
            "sub-maps must not share a key",
            parts.sumOf { it.size }, parts.flatMap { it.keys }.toSet().size,
        )
        parts.forEach { part ->
            part.forEach { (key, value) ->
                assertEquals("$key must reach the merged map with the sub-map's value", value, merged[key])
            }
        }
    }

    @Test
    fun `grouped fields reach the flat map under their taxonomy names`() {
        val f = sample().copy(
            signal = ServingSignal(rsrq = -11, sinr = 14, cqi = 9, timingAdvance = 3, dbm = -84),
            neighbors = NeighborDetail(
                pcis = listOf(1, 2), earfcns = listOf(1600), rsrps = listOf(-90), rats = listOf("LTE", "LTE"),
                maxRsrp = -90, servingPciInNeighbors = false, distinctEarfcnCount = 1,
            ),
            capture = CaptureContext(
                origin = CaptureOrigin.PRIME, appForeground = true, screenInteractive = false,
                dataActivity = "IN", rawRecordCount = 3,
            ),
            sim = SimContext(
                mcc = "427", mnc = "01", operatorName = "Ooredoo",
                plmnMatchesSim = true, operatorNameMatchesSim = true,
            ),
            service = ServiceContext(state = "IN_SERVICE", isRoaming = false, dataNetworkType = "LTE"),
        ).toFieldMap()
        assertEquals(-11, f["serving_rsrq"])
        assertEquals(3, f["serving_timing_advance"])
        assertEquals(listOf(1, 2), f["neighbor_pcis"])
        assertEquals(false, f["serving_pci_in_neighbors"])
        assertEquals("PRIME", f["capture_origin"])
        assertEquals(false, f["screen_interactive"])
        assertEquals(3, f["raw_record_count"])
        assertEquals("427", f["sim_mcc"])
        assertEquals(true, f["plmn_matches_sim"])
        assertEquals("IN_SERVICE", f["service_state"])
        assertEquals(false, f["is_roaming"])
    }

    @Test
    fun `null measurements survive into the field map`() {
        val f = sample().copy(locationMovedMLast5m = null, servingRsrp = null).toFieldMap()
        assertNull(f["location_moved_m_last_5m"])
        assertNull(f["serving_rsrp"])
    }
}
