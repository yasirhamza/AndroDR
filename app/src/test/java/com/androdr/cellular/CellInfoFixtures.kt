package com.androdr.cellular

import android.telephony.CellIdentityGsm
import android.telephony.CellIdentityLte
import android.telephony.CellIdentityNr
import android.telephony.CellIdentityWcdma
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoWcdma
import android.telephony.CellSignalStrengthGsm
import android.telephony.CellSignalStrengthLte
import android.telephony.CellSignalStrengthNr
import android.telephony.CellSignalStrengthWcdma
import io.mockk.every
import io.mockk.mockk

/**
 * Mocked platform cell records, one per technology, with the values the
 * SM-F971B capture actually showed (LTE) or plausible ones (the rest).
 *
 * Every accessor CellReader touches is stubbed explicitly: an unstubbed
 * call on a strict mock throws, which is the point — a reader that starts
 * consulting a new field fails here rather than silently at runtime.
 */
object CellInfoFixtures {

    const val UNAVAILABLE = Int.MAX_VALUE
    const val UNAVAILABLE_LONG = Long.MAX_VALUE

    fun lte(
        registered: Boolean = true,
        tac: Int = 1437,
        ci: Int = 192816407,
        pci: Int = 167,
        earfcn: Int = 1600,
        rsrp: Int = -84,
        bandwidth: Int = UNAVAILABLE,
        bands: IntArray = intArrayOf(3),
        rsrq: Int = -11,
        rssnr: Int = 10,
        cqi: Int = UNAVAILABLE,
        timingAdvance: Int = UNAVAILABLE,
    ): CellInfoLte {
        val identity = mockk<CellIdentityLte> {
            every { mccString } returns "427"
            every { mncString } returns "01"
            every { this@mockk.tac } returns tac
            every { this@mockk.ci } returns ci
            every { this@mockk.pci } returns pci
            every { this@mockk.earfcn } returns earfcn
            every { this@mockk.bands } returns bands
            every { this@mockk.bandwidth } returns bandwidth
            every { operatorAlphaLong } returns "Ooredoo"
            every { operatorAlphaShort } returns "Ooredoo"
            every { additionalPlmns } returns emptySet()
        }
        val signal = mockk<CellSignalStrengthLte> {
            every { this@mockk.rsrp } returns rsrp
            every { this@mockk.rsrq } returns rsrq
            every { this@mockk.rssnr } returns rssnr
            every { this@mockk.cqi } returns cqi
            every { this@mockk.timingAdvance } returns timingAdvance
            every { dbm } returns rsrp
        }
        return mockk {
            every { isRegistered } returns registered
            every { cellIdentity } returns identity
            every { cellSignalStrength } returns signal
        }
    }

    fun nr(
        registered: Boolean = true,
        tac: Int = 1437,
        nci: Long = 3_456_789_012L,
        pci: Int = 301,
        nrarfcn: Int = 640_000,
        ssRsrp: Int = -90,
        ssRsrq: Int = -12,
        ssSinr: Int = 15,
    ): CellInfoNr {
        val identity = mockk<CellIdentityNr> {
            every { mccString } returns "427"
            every { mncString } returns "01"
            every { this@mockk.tac } returns tac
            every { this@mockk.nci } returns nci
            every { this@mockk.pci } returns pci
            every { this@mockk.nrarfcn } returns nrarfcn
            every { bands } returns intArrayOf(78)
            every { operatorAlphaLong } returns "Ooredoo"
            every { operatorAlphaShort } returns "Ooredoo"
            every { additionalPlmns } returns emptySet()
        }
        // timingAdvanceMicros is not stubbed: the reader consults it only on
        // API 34+, and these tests run with SDK_INT = 0.
        val signal = mockk<CellSignalStrengthNr> {
            every { this@mockk.ssRsrp } returns ssRsrp
            every { this@mockk.ssRsrq } returns ssRsrq
            every { this@mockk.ssSinr } returns ssSinr
            every { dbm } returns ssRsrp
        }
        return mockk {
            every { isRegistered } returns registered
            every { cellIdentity } returns identity
            every { cellSignalStrength } returns signal
        }
    }

    fun wcdma(
        registered: Boolean = true,
        lac: Int = 2210,
        cid: Int = 44_112_233,
        psc: Int = 77,
        uarfcn: Int = 10_688,
    ): CellInfoWcdma {
        val identity = mockk<CellIdentityWcdma> {
            every { mccString } returns "427"
            every { mncString } returns "01"
            every { this@mockk.lac } returns lac
            every { this@mockk.cid } returns cid
            every { this@mockk.psc } returns psc
            every { this@mockk.uarfcn } returns uarfcn
            every { operatorAlphaLong } returns "Ooredoo"
            every { operatorAlphaShort } returns "Ooredoo"
            every { additionalPlmns } returns emptySet()
        }
        val signal = mockk<CellSignalStrengthWcdma> { every { dbm } returns -79 }
        return mockk {
            every { isRegistered } returns registered
            every { cellIdentity } returns identity
            every { cellSignalStrength } returns signal
        }
    }

    fun gsm(registered: Boolean = true, lac: Int = 2210, cid: Int = 5011, arfcn: Int = 62): CellInfoGsm {
        val identity = mockk<CellIdentityGsm> {
            every { mccString } returns "427"
            every { mncString } returns "01"
            every { this@mockk.lac } returns lac
            every { this@mockk.cid } returns cid
            every { this@mockk.arfcn } returns arfcn
            every { operatorAlphaLong } returns "Ooredoo"
            every { operatorAlphaShort } returns "Ooredoo"
            every { additionalPlmns } returns emptySet()
        }
        val signal = mockk<CellSignalStrengthGsm> { every { dbm } returns -71 }
        return mockk {
            every { isRegistered } returns registered
            every { cellIdentity } returns identity
            every { cellSignalStrength } returns signal
        }
    }

    /** A serving cell plus [neighbours] LTE neighbours at [neighbourRsrp]. */
    fun lteList(neighbours: Int = 13, neighbourRsrp: Int = -95): List<CellInfo> =
        listOf(lte()) + List(neighbours) { lte(registered = false, rsrp = neighbourRsrp) }
}
