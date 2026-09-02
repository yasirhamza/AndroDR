package com.androdr.cellular

import android.os.Build
import android.telephony.CellIdentityGsm
import android.telephony.CellIdentityLte
import android.telephony.CellIdentityNr
import android.telephony.CellIdentityWcdma
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoWcdma
import android.telephony.CellSignalStrengthNr
import androidx.annotation.RequiresApi
import com.androdr.data.model.NeighborDetail
import com.androdr.data.model.ServingSignal

/**
 * Reads identity and signal out of a [CellInfo] of any technology.
 *
 * `toSnapshot()` understood LTE only: on NR, WCDMA or GSM every identity
 * field went null while `rat` still named the technology — a snapshot that
 * described a radio without a cell, on exactly the transitions (LTE to NR,
 * LTE to GSM) the RAT-downgrade rule exists to see. It never showed because
 * the capture device stayed on LTE.
 *
 * FIELD NAMES ARE LTE-FLAVOURED BY CONVENTION. The rules and the taxonomy
 * key on `tac`, `ci`, `pci`, `earfcn`; each carries the technology's
 * equivalent — the area code (TAC / LAC), the cell (CI / NCI / CID), the
 * physical-layer id (PCI / PSC; GSM has none) and the channel number
 * (EARFCN / NRARFCN / UARFCN / ARFCN). `rat` says which reading applies.
 *
 * Only reached on API 31+ (the monitor does not arm below that), so every
 * accessor used here exists. The JVM tests run with SDK_INT = 0 against
 * mocks, which is why nothing here consults Build.VERSION at runtime.
 */
@RequiresApi(Build.VERSION_CODES.S)
internal object CellReader {

    /** Technology-neutral identity of one cell. */
    data class Identity(
        val rat: String,
        val mcc: String?,
        val mnc: String?,
        val tac: Int?,
        val ci: Long?,
        val pci: Int?,
        val earfcn: Int?,
        val bands: List<Int>,
        val bandwidthKhz: Int?,
        val operatorAlphaLong: String?,
        val operatorAlphaShort: String?,
        val additionalPlmns: List<String>,
    )

    fun rat(cell: CellInfo): String = when (cell) {
        is CellInfoNr -> "NR"
        is CellInfoLte -> "LTE"
        is CellInfoWcdma -> "UMTS"
        is CellInfoGsm -> "GSM"
        else -> "UNKNOWN"
    }

    fun identity(cell: CellInfo): Identity = when (cell) {
        is CellInfoNr -> (cell.cellIdentity as? CellIdentityNr)?.let(::nr)
        is CellInfoLte -> lte(cell.cellIdentity)
        is CellInfoWcdma -> wcdma(cell.cellIdentity)
        is CellInfoGsm -> gsm(cell.cellIdentity)
        else -> null
    } ?: unknown(rat(cell))

    /**
     * Reference-signal received power of the cell. LTE RSRP and NR SS-RSRP
     * are the same measurement class; 3G and 2G have no RSRP, so this is
     * null there rather than a different quantity under the same name.
     */
    fun rsrp(cell: CellInfo): Int? = when (cell) {
        is CellInfoNr -> (cell.cellSignalStrength as? CellSignalStrengthNr)?.ssRsrp?.let(::sentinel)
        is CellInfoLte -> sentinel(cell.cellSignalStrength.rsrp)
        else -> null
    }

    /**
     * Signal quality beyond RSRP. RSRQ/SINR/CQI/timing advance exist on LTE
     * (and RSRQ/SINR on NR); `dbm` is the platform's technology-generic
     * level and is read on every recognised RAT.
     *
     * Timing advance is the one to watch: it is the round-trip distance to
     * the serving tower in ~78 m units, so a serving cell that is suddenly
     * very close is visible here and nowhere else in Tier 1.
     *
     * Dispatches on the record type, like [rsrp], rather than on the signal
     * object: each subtype's `getCellSignalStrength()` is a covariant
     * override, and only the typed accessor is what the fixtures stub.
     */
    fun signal(cell: CellInfo): ServingSignal = when (cell) {
        is CellInfoLte -> cell.cellSignalStrength.let { ss ->
            ServingSignal(
                rsrq = sentinel(ss.rsrq),
                sinr = sentinel(ss.rssnr),
                cqi = sentinel(ss.cqi),
                timingAdvance = sentinel(ss.timingAdvance),
                dbm = sentinel(ss.dbm),
            )
        }
        is CellInfoNr -> (cell.cellSignalStrength as? CellSignalStrengthNr)?.let { ss ->
            ServingSignal(
                rsrq = sentinel(ss.ssRsrq),
                sinr = sentinel(ss.ssSinr),
                timingAdvanceUs = nrTimingAdvanceMicros(ss),
                dbm = sentinel(ss.dbm),
            )
        } ?: ServingSignal()
        is CellInfoWcdma -> ServingSignal(dbm = sentinel(cell.cellSignalStrength.dbm))
        is CellInfoGsm -> ServingSignal(dbm = sentinel(cell.cellSignalStrength.dbm))
        else -> ServingSignal()
    }

    /**
     * The neighbour list as parallel scalar lists plus the scalars a rule
     * needs but cannot derive (the evaluator has no cross-list reasoning).
     * Each list holds only the values that were available, in report order.
     */
    fun neighbors(serving: Identity, neighbours: List<CellInfo>): NeighborDetail {
        val ids = neighbours.map(::identity)
        val pcis = ids.mapNotNull { it.pci }
        val earfcns = ids.mapNotNull { it.earfcn }
        val rsrps = neighbours.mapNotNull(::rsrp)
        return NeighborDetail(
            pcis = pcis,
            earfcns = earfcns,
            rsrps = rsrps,
            rats = ids.map { it.rat },
            maxRsrp = rsrps.maxOrNull(),
            // A serving PCI that also appears as a neighbour is two cells
            // claiming one physical-layer id — but only decidable when the
            // serving PCI is known and at least one neighbour reported one.
            servingPciInNeighbors = if (serving.pci == null || pcis.isEmpty()) null else serving.pci in pcis,
            distinctEarfcnCount = earfcns.distinct().size,
        )
    }

    /** NR timing advance arrived in API 34; below that the platform has no such reading. */
    private fun nrTimingAdvanceMicros(ss: CellSignalStrengthNr): Int? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) sentinel(ss.timingAdvanceMicros) else null

    private fun lte(id: CellIdentityLte) = Identity(
        rat = "LTE",
        mcc = id.mccString,
        mnc = id.mncString,
        tac = sentinel(id.tac),
        ci = sentinel(id.ci)?.toLong(),
        pci = sentinel(id.pci),
        earfcn = sentinel(id.earfcn),
        bands = id.bands.toList(),
        bandwidthKhz = sentinel(id.bandwidth),
        operatorAlphaLong = id.operatorAlphaLong?.toString(),
        operatorAlphaShort = id.operatorAlphaShort?.toString(),
        additionalPlmns = id.additionalPlmns.toList(),
    )

    private fun nr(id: CellIdentityNr) = Identity(
        rat = "NR",
        mcc = id.mccString,
        mnc = id.mncString,
        tac = sentinel(id.tac),
        ci = sentinel(id.nci),
        pci = sentinel(id.pci),
        earfcn = sentinel(id.nrarfcn),
        bands = id.bands.toList(),
        // NR carrier bandwidth is not exposed by CellIdentityNr.
        bandwidthKhz = null,
        operatorAlphaLong = id.operatorAlphaLong?.toString(),
        operatorAlphaShort = id.operatorAlphaShort?.toString(),
        additionalPlmns = id.additionalPlmns.toList(),
    )

    private fun wcdma(id: CellIdentityWcdma) = Identity(
        rat = "UMTS",
        mcc = id.mccString,
        mnc = id.mncString,
        tac = sentinel(id.lac),
        ci = sentinel(id.cid)?.toLong(),
        pci = sentinel(id.psc),
        earfcn = sentinel(id.uarfcn),
        bands = emptyList(),
        bandwidthKhz = null,
        operatorAlphaLong = id.operatorAlphaLong?.toString(),
        operatorAlphaShort = id.operatorAlphaShort?.toString(),
        additionalPlmns = id.additionalPlmns.toList(),
    )

    private fun gsm(id: CellIdentityGsm) = Identity(
        rat = "GSM",
        mcc = id.mccString,
        mnc = id.mncString,
        tac = sentinel(id.lac),
        ci = sentinel(id.cid)?.toLong(),
        // GSM's BSIC is a colour code, not a physical-layer cell id.
        pci = null,
        earfcn = sentinel(id.arfcn),
        bands = emptyList(),
        bandwidthKhz = null,
        operatorAlphaLong = id.operatorAlphaLong?.toString(),
        operatorAlphaShort = id.operatorAlphaShort?.toString(),
        additionalPlmns = id.additionalPlmns.toList(),
    )

    private fun unknown(rat: String) = Identity(
        rat = rat,
        mcc = null, mnc = null, tac = null, ci = null, pci = null, earfcn = null,
        bands = emptyList(), bandwidthKhz = null,
        operatorAlphaLong = null, operatorAlphaShort = null, additionalPlmns = emptyList(),
    )

    /** Android reports an unavailable integer as [CellInfo.UNAVAILABLE] (Integer.MAX_VALUE). */
    fun sentinel(value: Int): Int? = if (value == Int.MAX_VALUE) null else value

    /** The 64-bit equivalent, [CellInfo.UNAVAILABLE_LONG]; NCI is the one field that needs it. */
    fun sentinel(value: Long): Long? = if (value == Long.MAX_VALUE) null else value
}
