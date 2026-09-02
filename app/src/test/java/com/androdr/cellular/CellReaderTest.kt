package com.androdr.cellular

import android.telephony.CellInfo
import com.androdr.data.model.ServingSignal
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Identity extraction was LTE-only: on any other technology every identity
 * field went null while `rat` still named the technology. The RAT-downgrade
 * rule fires on exactly those transitions, so its finding would have carried
 * a snapshot with no cell in it.
 */
class CellReaderTest {

    @Test
    fun `LTE identity and RSRP are read in full`() {
        val id = CellReader.identity(CellInfoFixtures.lte(bandwidth = 20_000))
        assertEquals("LTE", id.rat)
        assertEquals("427", id.mcc)
        assertEquals("01", id.mnc)
        assertEquals(1437, id.tac)
        assertEquals(192816407L, id.ci)
        assertEquals(167, id.pci)
        assertEquals(1600, id.earfcn)
        assertEquals(listOf(3), id.bands)
        assertEquals(20_000, id.bandwidthKhz)
        assertEquals("Ooredoo", id.operatorAlphaLong)
        assertEquals(-84, CellReader.rsrp(CellInfoFixtures.lte()))
    }

    @Test
    fun `NR maps NCI, NRARFCN and SS-RSRP onto the shared field names`() {
        val cell = CellInfoFixtures.nr()
        val id = CellReader.identity(cell)
        assertEquals("NR", id.rat)
        assertEquals(1437, id.tac)
        assertEquals(3_456_789_012L, id.ci)
        assertEquals(301, id.pci)
        assertEquals(640_000, id.earfcn)
        assertEquals(listOf(78), id.bands)
        assertNull("CellIdentityNr exposes no bandwidth", id.bandwidthKhz)
        assertEquals(-90, CellReader.rsrp(cell))
    }

    @Test
    fun `WCDMA maps LAC, CID, PSC and UARFCN and has no RSRP`() {
        val cell = CellInfoFixtures.wcdma()
        val id = CellReader.identity(cell)
        assertEquals("UMTS", id.rat)
        assertEquals(2210, id.tac)
        assertEquals(44_112_233L, id.ci)
        assertEquals(77, id.pci)
        assertEquals(10_688, id.earfcn)
        assertNull("3G has RSCP, not RSRP; a different quantity must not wear the same name", CellReader.rsrp(cell))
    }

    @Test
    fun `GSM maps LAC, CID and ARFCN, with no physical-layer id`() {
        val cell = CellInfoFixtures.gsm()
        val id = CellReader.identity(cell)
        assertEquals("GSM", id.rat)
        assertEquals(2210, id.tac)
        assertEquals(5011L, id.ci)
        assertNull("BSIC is a colour code, not a PCI", id.pci)
        assertEquals(62, id.earfcn)
        assertNull(CellReader.rsrp(cell))
    }

    @Test
    fun `the unavailable sentinel becomes null on every technology, including the 64-bit NCI`() {
        val lte = CellReader.identity(
            CellInfoFixtures.lte(
                tac = CellInfoFixtures.UNAVAILABLE, ci = CellInfoFixtures.UNAVAILABLE,
                pci = CellInfoFixtures.UNAVAILABLE, earfcn = CellInfoFixtures.UNAVAILABLE,
            ),
        )
        assertNull(lte.tac); assertNull(lte.ci); assertNull(lte.pci); assertNull(lte.earfcn)
        assertNull("bandwidth was Integer.MAX_VALUE on the F971B", lte.bandwidthKhz)

        val nr = CellReader.identity(CellInfoFixtures.nr(nci = CellInfoFixtures.UNAVAILABLE_LONG))
        assertNull("NCI is a Long; Integer.MAX_VALUE is a VALID NCI and Long.MAX_VALUE is the sentinel", nr.ci)
        assertEquals(Int.MAX_VALUE.toLong(), CellReader.identity(CellInfoFixtures.nr(nci = Int.MAX_VALUE.toLong())).ci)

        assertNull(CellReader.rsrp(CellInfoFixtures.lte(rsrp = CellInfoFixtures.UNAVAILABLE)))
        assertNull(CellReader.rsrp(CellInfoFixtures.nr(ssRsrp = CellInfoFixtures.UNAVAILABLE)))
    }

    @Test
    fun `an unrecognised record type yields UNKNOWN with nothing invented`() {
        val other = mockk<CellInfo> { every { isRegistered } returns true }
        val id = CellReader.identity(other)
        assertEquals("UNKNOWN", id.rat)
        assertNull(id.tac); assertNull(id.ci); assertNull(id.earfcn); assertNull(id.mcc)
        assertNull(CellReader.rsrp(other))
        assertEquals("no signal reading is invented either", ServingSignal(), CellReader.signal(other))
    }

    // ---- signal quality --------------------------------------------------

    @Test
    fun `LTE signal quality is read in full, with the sentinel honoured per field`() {
        val s = CellReader.signal(CellInfoFixtures.lte(rsrq = -11, rssnr = 10, cqi = 9, timingAdvance = 12))
        assertEquals(-11, s.rsrq)
        assertEquals(10, s.sinr)
        assertEquals(9, s.cqi)
        assertEquals(12, s.timingAdvance)
        assertEquals("dbm is the generic level; the fixture reports RSRP there", -84, s.dbm)
        assertNull("NR-only", s.timingAdvanceUs)

        val idle = CellReader.signal(CellInfoFixtures.lte())
        assertEquals(-11, idle.rsrq)
        assertNull("CQI is Integer.MAX_VALUE when the modem is idle", idle.cqi)
        assertNull("so is timing advance on the F971B capture", idle.timingAdvance)
    }

    @Test
    fun `NR reads SS-RSRQ and SS-SINR under the shared names and no LTE-only fields`() {
        val s = CellReader.signal(CellInfoFixtures.nr())
        assertEquals(-12, s.rsrq)
        assertEquals(15, s.sinr)
        assertEquals(-90, s.dbm)
        assertNull("CQI is an LTE reading", s.cqi)
        assertNull("LTE timing advance is not NR's", s.timingAdvance)
        assertNull("NR timing advance needs API 34; the JVM reports SDK_INT 0", s.timingAdvanceUs)
    }

    @Test
    fun `3G and 2G carry only the generic level`() {
        val umts = CellReader.signal(CellInfoFixtures.wcdma())
        assertEquals(-79, umts.dbm)
        assertNull(umts.rsrq); assertNull(umts.sinr); assertNull(umts.cqi); assertNull(umts.timingAdvance)
        val gsm = CellReader.signal(CellInfoFixtures.gsm())
        assertEquals(-71, gsm.dbm)
        assertNull(gsm.rsrq)
    }

    // ---- neighbour list ---------------------------------------------------

    private fun neighbour(pci: Int, earfcn: Int, rsrp: Int) =
        CellInfoFixtures.lte(registered = false, pci = pci, earfcn = earfcn, rsrp = rsrp)

    @Test
    fun `neighbours become parallel lists plus the scalars a rule cannot derive`() {
        val serving = CellReader.identity(CellInfoFixtures.lte(pci = 167, earfcn = 1600))
        val n = CellReader.neighbors(
            serving,
            listOf(neighbour(12, 1600, -95), neighbour(45, 1850, -101), neighbour(78, 1600, -88)),
        )
        assertEquals(listOf(12, 45, 78), n.pcis)
        assertEquals(listOf(1600, 1850, 1600), n.earfcns)
        assertEquals(listOf(-95, -101, -88), n.rsrps)
        assertEquals(listOf("LTE", "LTE", "LTE"), n.rats)
        assertEquals(-88, n.maxRsrp)
        assertEquals(2, n.distinctEarfcnCount)
        assertEquals(false, n.servingPciInNeighbors)
    }

    @Test
    fun `a neighbour that repeats the serving PCI is flagged`() {
        val serving = CellReader.identity(CellInfoFixtures.lte(pci = 167))
        val n = CellReader.neighbors(serving, listOf(neighbour(12, 1600, -95), neighbour(167, 1850, -90)))
        assertEquals(true, n.servingPciInNeighbors)
    }

    @Test
    fun `the PCI clash is undecidable, not false, when either side has no PCI`() {
        val lte = CellReader.identity(CellInfoFixtures.lte(pci = 167))
        assertNull("no neighbours at all", CellReader.neighbors(lte, emptyList()).servingPciInNeighbors)
        assertNull(
            "neighbours without a PCI (GSM) cannot clash",
            CellReader.neighbors(lte, listOf(CellInfoFixtures.gsm(registered = false))).servingPciInNeighbors,
        )
        val gsmServing = CellReader.identity(CellInfoFixtures.gsm())
        assertNull(
            "a serving cell without a PCI cannot clash either",
            CellReader.neighbors(gsmServing, listOf(neighbour(12, 1600, -95))).servingPciInNeighbors,
        )
    }

    @Test
    fun `the lists hold only what was available, so an unavailable value is skipped not zeroed`() {
        val serving = CellReader.identity(CellInfoFixtures.lte())
        val n = CellReader.neighbors(
            serving,
            listOf(
                neighbour(CellInfoFixtures.UNAVAILABLE, CellInfoFixtures.UNAVAILABLE, CellInfoFixtures.UNAVAILABLE),
                neighbour(45, 1850, -101),
            ),
        )
        assertEquals(listOf(45), n.pcis)
        assertEquals(listOf(1850), n.earfcns)
        assertEquals(listOf(-101), n.rsrps)
        assertEquals("the RAT of every record is known even when its numbers are not", 2, n.rats.size)
        assertEquals(-101, n.maxRsrp)
    }

    @Test
    fun `a mixed-technology neighbour list keeps every record's RAT and only LTE and NR levels`() {
        val serving = CellReader.identity(CellInfoFixtures.lte())
        val n = CellReader.neighbors(
            serving,
            listOf(CellInfoFixtures.nr(registered = false), CellInfoFixtures.wcdma(registered = false)),
        )
        assertEquals(listOf("NR", "UMTS"), n.rats)
        assertEquals("3G has no RSRP", listOf(-90), n.rsrps)
        assertTrue(n.pcis.containsAll(listOf(301, 77)))
        assertFalse("the serving LTE PCI is not among them", n.servingPciInNeighbors == true)
    }
}
