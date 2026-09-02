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
 *
 * The identity fields are LTE-flavoured by convention and carry each
 * technology's equivalent (TAC/LAC, CI/NCI/CID, PCI/PSC, EARFCN/NRARFCN/
 * UARFCN/ARFCN); `rat` says which reading applies. See `CellReader`.
 *
 * The grouped fields ([signal], [neighbors], [capture], [sim], [service])
 * default to "nothing known" so the many fixtures that predate them still
 * construct; their keys are merged flat into [toFieldMap] because the rule
 * grammar addresses fields by a single name.
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
    /** Age of the passive location fix behind [locationMovedMLast5m]; null when there is no fix. */
    val locationFixAgeS: Int? = null,
    val signal: ServingSignal = ServingSignal(),
    val neighbors: NeighborDetail = NeighborDetail(),
    val capture: CaptureContext = CaptureContext(),
    val sim: SimContext = SimContext(),
    val service: ServiceContext = ServiceContext(),
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
        "location_fix_age_s" to locationFixAgeS,
    ) + signal.toFieldMap() + neighbors.toFieldMap() + capture.toFieldMap() +
        sim.toFieldMap() + service.toFieldMap()

    /**
     * The raw radio facts of this observation: what the platform reported,
     * minus WHEN it reported it, the circumstances of the read, and what the
     * emitter derived from earlier observations. Two deliveries with equal
     * keys describe the same physical radio state, which is how a repeated
     * delivery is told apart from a new one. See `DuplicateDeliveryFilter`.
     */
    fun observationKey(): Map<String, Any?> = toFieldMap() - NON_OBSERVATION_KEYS

    companion object {
        /**
         * Field-map keys that legitimately differ between two deliveries of
         * the same physical observation: the clock, the read's circumstances
         * (prime vs callback, screen state), and everything computed against
         * previous observations rather than read from the radio.
         */
        val NON_OBSERVATION_KEYS: Set<String> = setOf(
            "captured_at",
            "previous_tac",
            "previous_rat",
            "tac_changed",
            "rat_changed",
            "tac_changes_last_5m",
            "location_moved_m_last_5m",
            "location_fix_age_s",
            "capture_origin",
            "app_foreground",
            "screen_interactive",
            "data_activity",
        )
    }
}

/**
 * Serving-cell signal quality beyond RSRP. LTE and NR carry these; on 3G/2G
 * they are null rather than a different quantity under the same name.
 */
data class ServingSignal(
    /** RSRQ (LTE) or SS-RSRQ (NR), dB. */
    val rsrq: Int? = null,
    /** RSSNR (LTE) or SS-SINR (NR), dB. */
    val sinr: Int? = null,
    /** Channel quality indicator, LTE only. */
    val cqi: Int? = null,
    /** LTE timing advance in TA units (0..1282, ~78 m each). */
    val timingAdvance: Int? = null,
    /** NR timing advance in microseconds (API 34+). */
    val timingAdvanceUs: Int? = null,
    /** Technology-generic signal level from getDbm(); populated on every RAT. */
    val dbm: Int? = null,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "serving_rsrq" to rsrq,
        "serving_sinr" to sinr,
        "serving_cqi" to cqi,
        "serving_timing_advance" to timingAdvance,
        "serving_timing_advance_us" to timingAdvanceUs,
        "serving_signal_dbm" to dbm,
    )
}

/**
 * The neighbour list, as parallel scalar lists plus derived scalars.
 *
 * The evaluator matches a list field element-wise and cannot correlate
 * across two lists, so each list simply holds the values that were
 * available, in report order — a neighbour missing one value is absent from
 * that list only. Anything that needs cross-neighbour reasoning is derived
 * here as a scalar.
 */
data class NeighborDetail(
    val pcis: List<Int> = emptyList(),
    val earfcns: List<Int> = emptyList(),
    /** LTE RSRP / NR SS-RSRP, dBm. */
    val rsrps: List<Int> = emptyList(),
    val rats: List<String> = emptyList(),
    val maxRsrp: Int? = null,
    /** Null when the serving PCI is unknown or there are no neighbours. */
    val servingPciInNeighbors: Boolean? = null,
    val distinctEarfcnCount: Int = 0,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "neighbor_pcis" to pcis,
        "neighbor_earfcns" to earfcns,
        "neighbor_rsrps" to rsrps,
        "neighbor_rats" to rats,
        "neighbor_max_rsrp" to maxRsrp,
        "serving_pci_in_neighbors" to servingPciInNeighbors,
        "neighbor_distinct_earfcn_count" to distinctEarfcnCount,
    )
}

/**
 * The circumstances of the read. A neighbour list can be empty because the
 * radio is idle (3GPP 36.304: a UE in RRC_IDLE with a strong serving cell
 * does not measure neighbours) or because the caller lacked standing; these
 * fields let a rule tell those apart from a genuinely isolated cell.
 */
data class CaptureContext(
    val origin: CaptureOrigin = CaptureOrigin.CALLBACK,
    val appForeground: Boolean? = null,
    val screenInteractive: Boolean? = null,
    /** NONE, IN, OUT, INOUT or DORMANT. */
    val dataActivity: String? = null,
    /** Records in the platform's list, serving included. */
    val rawRecordCount: Int = 0,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "capture_origin" to origin.name,
        "app_foreground" to appForeground,
        "screen_interactive" to screenInteractive,
        "data_activity" to dataActivity,
        "raw_record_count" to rawRecordCount,
    )
}

/**
 * What the SIM says the home network is — the sturdier side of an operator
 * comparison, because the serving cell's operator name is attacker-chosen
 * while the SIM's is not.
 */
data class SimContext(
    val mcc: String? = null,
    val mnc: String? = null,
    /** Service provider name from the SIM. */
    val operatorName: String? = null,
    /** Serving PLMN equals the SIM PLMN; null when either side is unknown. */
    val plmnMatchesSim: Boolean? = null,
    /** Serving operator name agrees with the SIM's; null when either side is blank. */
    val operatorNameMatchesSim: Boolean? = null,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "sim_mcc" to mcc,
        "sim_mnc" to mnc,
        "sim_operator_name" to operatorName,
        "plmn_matches_sim" to plmnMatchesSim,
        "operator_name_matches_sim" to operatorNameMatchesSim,
    )
}

/** Registration state from ServiceState, read alongside the cell list. */
data class ServiceContext(
    /** IN_SERVICE, OUT_OF_SERVICE, EMERGENCY_ONLY, POWER_OFF or UNKNOWN. */
    val state: String? = null,
    val isRoaming: Boolean? = null,
    /** TelephonyManager network type name of the data connection, e.g. LTE, NR. */
    val dataNetworkType: String? = null,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "service_state" to state,
        "is_roaming" to isRoaming,
        "data_network_type" to dataNetworkType,
    )
}
