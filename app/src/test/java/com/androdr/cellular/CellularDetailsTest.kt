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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The vocabulary is written once and classified once. Three hand-written
 * copies of it drifted: `bands` reached the shared report without ever being
 * cleared for export, and a dead `prevTac` sat in the allowlist only to be
 * subtracted again. These tests make the next drift a build failure.
 */
class CellularDetailsTest {

    private fun snapshot() = CellularSnapshot(
        mcc = "427", mnc = "01", tac = 1437, ci = 192816407L, pci = 167,
        earfcn = 1600, bands = listOf(3), bandwidthKhz = 20000, rat = "LTE",
        operatorAlphaLong = "Ooredoo", operatorAlphaShort = "Ooredoo",
        additionalPlmns = emptyList(), neighborCount = 2, servingRsrp = -84,
        isRegistered = true, capturedAt = 1000L, source = TelemetrySource.LIVE_SCAN,
        previousTac = 1436, previousRat = "LTE", tacChanged = true, ratChanged = false,
        tacChangesLast5m = 4, servingMinusMaxNeighborRsrpDb = 11,
        locationMovedMLast5m = 640, locationFixAgeS = 12,
        signal = ServingSignal(rsrq = -11, sinr = 10, cqi = 9, timingAdvance = 4, timingAdvanceUs = null, dbm = -84),
        neighbors = NeighborDetail(
            pcis = listOf(12, 167), earfcns = listOf(1600, 1850), rsrps = listOf(-95, -101),
            rats = listOf("LTE", "LTE"), maxRsrp = -95, servingPciInNeighbors = true, distinctEarfcnCount = 2,
        ),
        capture = CaptureContext(
            origin = CaptureOrigin.PRIME, appForeground = false, screenInteractive = true,
            dataActivity = "NONE", rawRecordCount = 3,
        ),
        sim = SimContext(
            mcc = "427", mnc = "01", operatorName = "Ooredoo",
            plmnMatchesSim = true, operatorNameMatchesSim = true,
        ),
        service = ServiceContext(state = "IN_SERVICE", isRoaming = false, dataNetworkType = "LTE"),
    )

    private fun emittedKeys() = CellularDetails.pairs(snapshot()).map { it.first }

    @Test
    fun `every emitted key is classified as exportable or withheld, and nothing is both`() {
        val emitted = emittedKeys().toSet()
        val unclassified = emitted - CellularRedaction.EXPORTABLE_KEYS - CellularRedaction.WITHHELD_KEYS
        assertTrue("a new key must be consciously placed: $unclassified", unclassified.isEmpty())
        val both = CellularRedaction.EXPORTABLE_KEYS intersect CellularRedaction.WITHHELD_KEYS
        assertTrue("a key cannot be both: $both", both.isEmpty())
    }

    @Test
    fun `the allowlist names no key that is never emitted`() {
        // A dead allowlist entry is a leak waiting for someone to emit it.
        val dead = CellularRedaction.EXPORTABLE_KEYS + CellularRedaction.WITHHELD_KEYS -
            emittedKeys().toSet() - CellularRedaction.SESSION_KEYS
        assertTrue("classified but never emitted: $dead", dead.isEmpty())
    }

    @Test
    fun `keys are emitted once each`() {
        val keys = emittedKeys()
        assertEquals("a duplicated key would be dropped by the redactor", keys.toSet().size, keys.size)
    }

    @Test
    fun `the report row is exactly what the redactor would let through`() {
        // One gate: the observation row in the report must not be a second,
        // hand-maintained opinion about what is exportable.
        val s = snapshot()
        assertEquals(
            CellularDetails.exportable(s) + " " + CellularRedaction.REDACTION_NOTE,
            CellularRedaction.redact(CellularDetails.format(s)),
        )
    }

    @Test
    fun `the full row carries identity and the exportable row does not`() {
        val full = CellularDetails.format(snapshot())
        val exported = CellularDetails.exportable(snapshot())
        listOf("tac=1437", "ci=192816407", "pci=167", "plmn=427/01", "op=Ooredoo", "prevTac=1436").forEach {
            assertTrue("timeline row must keep $it for adjudication", full.contains(it))
            assertFalse("report row leaked $it", exported.contains(it))
        }
        listOf("rat=LTE", "reg=true", "bands=3", "bw=20000", "margin=11", "prevRat=LTE", "churn5m=4").forEach {
            assertTrue("report row dropped $it", exported.contains(it))
        }
    }

    @Test
    fun `a value can never smuggle in a second pair`() {
        // The operator name is the one string the network chooses.
        val row = CellularDetails.format(snapshot().copy(operatorAlphaLong = "Evil rsrp=-1\nsvc=FORGED"))
        assertFalse(row.contains('\n'))
        assertEquals("one rsrp pair", 1, Regex("(^| )rsrp=").findAll(row).count())
        assertFalse(row.contains(" svc=FORGED"))
    }

    @Test
    fun `null prints as a dash so the column is still there`() {
        val row = CellularDetails.format(snapshot().copy(servingRsrp = null, bands = emptyList()))
        assertTrue(row.contains(" rsrp=- "))
        assertTrue(row.contains(" bands=- "))
    }
}
