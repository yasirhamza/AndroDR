package com.androdr.cellular

/**
 * Strips tower-locating values out of cellular finding context before it
 * leaves the device.
 *
 * The split is by DESTINATION, not by sensitivity:
 *
 *  - The app-private database keeps the full context. Adjudicating a Tier 1
 *    finding against Tier 2 ground truth after the fact is impossible without
 *    the snapshot it fired on, and that data never leaves the device on its
 *    own.
 *  - Anything handed off — a shared report, a timeline CSV — is redacted.
 *    A handoff artifact is *meant* to be copied around, so a location trail in
 *    one is worse than in logcat, not better.
 *
 * `tac`, `ci` and `pci` identify the serving tower and are therefore a
 * location. Everything else describes the RADIO CONDITION, which is the actual
 * evidence: that the tracking area changed four times is the finding; which
 * tracking areas they were is not needed to believe it.
 *
 * Allowlist rather than denylist: a new emitted field must be consciously
 * cleared for export instead of leaking because nobody remembered to ban it.
 * Every key [CellularDetails] emits is in exactly one of [EXPORTABLE_KEYS] and
 * [WITHHELD_KEYS]; a test enforces that, so adding a key without deciding is a
 * build failure rather than a leak.
 */
object CellularRedaction {

    /** The timeline `source` of every row this object is responsible for. */
    const val SOURCE = "cellular_monitor"

    /** Keys safe to hand off — radio condition, never tower identity. */
    internal val EXPORTABLE_KEYS: Set<String> = setOf(
        "rat",        // radio access technology
        "reg",        // registered on the serving cell, or camped with none
        "earfcn",     // channel number; network-wide, not cell-specific
        "bands",      // frequency bands; a property of the channel, not the tower
        "bw",         // bandwidth
        "neighbours", // count only
        "rsrp",       // signal strength
        // Signal quality of the serving cell: measurements, not identity.
        "rsrq",
        "sinr",
        "cqi",
        "ta",         // timing advance — distance to the tower, not its position
        "taUs",
        "dbm",
        // Neighbour list, reduced to scalars. The neighbours' PCIs and
        // channels stay on-device; a count of distinct channels and the
        // strongest level do not identify a tower.
        "nMaxRsrp",
        "nEarfcns",
        "pciInN",     // the serving PCI also appears among the neighbours
        "margin",     // serving RSRP minus the strongest neighbour
        // Change since the previous observation — what happened, not where.
        "prevRat",
        "tacChanged",
        "ratChanged",
        "churn5m",    // count of changes, not the values
        // Movement is a distance, never a position: how far, not where.
        "moved5m",
        "fixAge",
        // Circumstances of the read — facts about the device, not the tower.
        "origin",     // PRIME or CALLBACK
        "records",    // how many records the platform handed over
        "screen",     // screen interactive at the read
        "fg",         // an activity was visible at the read
        "data",       // data activity direction at the read
        // Agreement between the serving cell and the SIM — booleans only.
        // The SIM's own MCC/MNC/name (sim_mcc, sim_mnc, sim_operator_name)
        // are never written into details in the first place.
        "simPlmn",
        "simName",
        // Registration side of the radio: a state, a flag and a bearer name.
        "svc",
        "roaming",
        "dnt",
        // The session-start row carries this key alone.
        "monitor",
    )

    /**
     * Keys that stay on-device: each one locates the tower, and with it the
     * device. Named rather than implied so that a reader of the allowlist
     * can see what was decided against, not just what was decided for.
     */
    internal val WITHHELD_KEYS: Set<String> = setOf(
        "tac",        // tracking area
        "ci",         // cell identity
        "pci",        // physical cell id
        "plmn",       // serving network code
        "op",         // serving network name, as broadcast
        "prevTac",    // the previous tracking area is a location too
    )

    /** Keys emitted by no observation; they belong to other timeline rows. */
    internal val SESSION_KEYS: Set<String> = setOf("monitor")

    const val REDACTION_NOTE =
        "[cell identity (tac/ci/pci/plmn/operator) withheld -- location-identifying; " +
            "retained on-device for adjudication]"

    fun isExportable(key: String): Boolean = key in EXPORTABLE_KEYS

    /**
     * Returns [details] with only exportable `key=value` pairs kept, followed
     * by a note saying what was withheld and why. Silence would read as "there
     * was nothing more", which is the wrong impression for a forensic artifact.
     * The converse holds too: a row from which nothing was dropped (the
     * session-start row is `monitor=active` and no more) carries no note,
     * because "withheld" on it would read as "there was more".
     *
     * The row is trusted only as far as its shape: it is split on ANY
     * whitespace (a newline inside a value must not carry a forged pair onto
     * the next line of a CSV), a token that is not `key=value` is dropped, and
     * a key that appears more than once is dropped entirely — a value that
     * smuggled in a second `rsrp=` is indistinguishable from the real one, so
     * neither can be believed.
     */
    fun redact(details: String): String {
        if (details.isBlank()) return details
        val tokens = details.trim().split(WHITESPACE)
        val pairs = tokens.filter { PAIR.matches(it) }
        val occurrences = pairs.groupingBy { it.substringBefore('=') }.eachCount()
        val kept = pairs.filter { token ->
            val key = token.substringBefore('=')
            isExportable(key) && occurrences[key] == 1
        }
        return when {
            kept.size == tokens.size -> kept.joinToString(" ")
            kept.isEmpty() -> REDACTION_NOTE
            else -> kept.joinToString(" ") + " " + REDACTION_NOTE
        }
    }

    private val WHITESPACE = Regex("\\s+")
    private val PAIR = Regex("[A-Za-z0-9]+=[^\\s=]*")
}
