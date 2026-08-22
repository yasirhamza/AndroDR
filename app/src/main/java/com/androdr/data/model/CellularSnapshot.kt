package com.androdr.data.model

/**
 * Tier 1 radio telemetry — one observation of the serving cell and its
 * neighbours, derived entirely from public Android telephony APIs (no root,
 * no DIAG port).
 *
 * Emits ALL radio facts verbatim plus objective derived measurements. It never
 * decides what is suspicious: "the TAC changed" and "it changed N times in five
 * minutes" are measurements; "three changes without movement is churn" is a
 * judgment and belongs in the rules. See the spec's "measurement/judgment line".
 *
 * Integer fields are nullable because Android reports unavailable values as
 * `Integer.MAX_VALUE`; the emitter normalizes that sentinel to null so rules
 * never match on 2147483647 by accident.
 */
data class CellularSnapshot(
    val mcc: String?,
    val mnc: String?,
    val tac: Int?,
    val ci: Long?,
    val pci: Int?,
    val earfcn: Int?,
    val bands: List<Int>,
    val bandwidthKhz: Int?,
    val rat: String,
    val operatorAlphaLong: String?,
    val operatorAlphaShort: String?,
    val additionalPlmns: List<String>,
    val neighborCount: Int,
    val servingRsrp: Int?,
    val isRegistered: Boolean,
    val capturedAt: Long,
    val source: TelemetrySource,
    val previousTac: Int?,
    val previousRat: String?,
    val tacChanged: Boolean,
    val ratChanged: Boolean,
    val tacChangesLast5m: Int,
    val servingMinusMaxNeighborRsrpDb: Int?,
    val locationMovedMLast5m: Int?,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "mcc" to mcc,
        "mnc" to mnc,
        "tac" to tac,
        "ci" to ci,
        "pci" to pci,
        "earfcn" to earfcn,
        "bands" to bands,
        "bandwidth_khz" to bandwidthKhz,
        "rat" to rat,
        "operator_alpha_long" to operatorAlphaLong,
        "operator_alpha_short" to operatorAlphaShort,
        "additional_plmns" to additionalPlmns,
        "neighbor_count" to neighborCount,
        "serving_rsrp" to servingRsrp,
        "is_registered" to isRegistered,
        "captured_at" to capturedAt,
        "source" to source.name,
        "previous_tac" to previousTac,
        "previous_rat" to previousRat,
        "tac_changed" to tacChanged,
        "rat_changed" to ratChanged,
        "tac_changes_last_5m" to tacChangesLast5m,
        "serving_minus_max_neighbor_rsrp_db" to servingMinusMaxNeighborRsrpDb,
        "location_moved_m_last_5m" to locationMovedMLast5m,
    )
}
