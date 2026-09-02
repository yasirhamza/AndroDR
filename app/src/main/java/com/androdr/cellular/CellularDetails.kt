package com.androdr.cellular

import com.androdr.data.model.CellularSnapshot

/**
 * The one `key=value` serialisation of a cellular observation.
 *
 * There used to be three hand-written copies of this vocabulary — the
 * timeline row in the monitor, the observation row in the report and the
 * export allowlist — each grown on its own, so a key could reach the shared
 * report without ever passing the allowlist (`bands` did). Now [pairs] is the
 * only place a key is named, [CellularRedaction] classifies every one of
 * them as exportable or withheld, and a test fails when the two disagree.
 *
 * Values never contain whitespace: numbers, booleans and enum names cannot,
 * and the one string the network chooses (the operator name) is folded by
 * `CellReader` before it gets here, and folded again here in case another
 * path ever supplies it. That is what lets the redactor split on whitespace
 * and treat every token as exactly one pair.
 */
object CellularDetails {

    /** Every fact of the observation, tower identity first, in a fixed order. */
    fun pairs(s: CellularSnapshot): List<Pair<String, String>> = listOf(
        "rat" to s.rat,
        "reg" to s.isRegistered,
        "tac" to s.tac,
        "ci" to s.ci,
        "pci" to s.pci,
        "earfcn" to s.earfcn,
        "bands" to s.bands.joinToString(",").ifEmpty { null },
        "bw" to s.bandwidthKhz,
        "plmn" to "${s.mcc ?: "-"}/${s.mnc ?: "-"}",
        "op" to s.operatorAlphaLong,
        "neighbours" to s.neighborCount,
        "rsrp" to s.servingRsrp,
        "rsrq" to s.signal.rsrq,
        "sinr" to s.signal.sinr,
        "cqi" to s.signal.cqi,
        "ta" to s.signal.timingAdvance,
        "taUs" to s.signal.timingAdvanceUs,
        "dbm" to s.signal.dbm,
        "nMaxRsrp" to s.neighbors.maxRsrp,
        "nEarfcns" to s.neighbors.distinctEarfcnCount,
        "pciInN" to s.neighbors.servingPciInNeighbors,
        "margin" to s.servingMinusMaxNeighborRsrpDb,
        "prevTac" to s.previousTac,
        "prevRat" to s.previousRat,
        "tacChanged" to s.tacChanged,
        "ratChanged" to s.ratChanged,
        "churn5m" to s.tacChangesLast5m,
        "moved5m" to s.locationMovedMLast5m,
        "fixAge" to s.locationFixAgeS,
        "origin" to s.capture.origin.name,
        "records" to s.capture.rawRecordCount,
        "screen" to s.capture.screenInteractive,
        "fg" to s.capture.appForeground,
        "data" to s.capture.dataActivity,
        "simPlmn" to s.sim.plmnMatchesSim,
        "simName" to s.sim.operatorNameMatchesSim,
        "svc" to s.service.state,
        "roaming" to s.service.isRoaming,
        "dnt" to s.service.dataNetworkType,
    ).map { (key, value) -> key to render(value) }

    /**
     * The full row for the app-private timeline. Tower identity is included —
     * this row never leaves the database on its own — and [CellularRedaction]
     * decides what leaves. Neighbour PCIs and the SIM's own identity are
     * deliberately absent: the counts and comparison results carry the evidence.
     */
    fun format(s: CellularSnapshot): String = join(pairs(s))

    /** The exportable pairs only — one observation row in a shared report. */
    fun exportable(s: CellularSnapshot): String =
        join(pairs(s).filter { (key, _) -> CellularRedaction.isExportable(key) })

    private fun join(pairs: List<Pair<String, String>>): String =
        pairs.joinToString(" ") { (key, value) -> "$key=$value" }

    /** Null prints as `-`; any whitespace in a value would split it into a forged pair. */
    private fun render(value: Any?): String =
        value?.toString()?.replace(WHITESPACE, "_") ?: "-"

    private val WHITESPACE = Regex("\\s+")
}
