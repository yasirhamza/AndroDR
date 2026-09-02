package com.androdr.cellular

import android.telephony.CellInfo
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
    }
}
