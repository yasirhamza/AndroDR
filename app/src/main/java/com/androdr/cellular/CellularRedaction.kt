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
 */
object CellularRedaction {

    /** Keys safe to hand off — radio condition, never tower identity. */
    private val EXPORTABLE_KEYS = setOf(
        "rat",        // radio access technology
        "earfcn",     // channel number; network-wide, not cell-specific
        "bw",         // bandwidth
        "neighbours", // count only
        "rsrp",       // signal strength
        "prevTac",    // REDACTED below — listed here only to be explicit it is not exportable
        "churn5m",    // count of changes, not the values
        "tacChanged",
        "ratChanged",
    ) - setOf("prevTac")

    const val REDACTION_NOTE =
        "[cell identity (tac/ci/pci/plmn/operator) withheld — location-identifying; " +
            "retained on-device for adjudication]"

    /**
     * Returns [details] with only exportable `key=value` pairs kept, followed
     * by a note saying what was withheld and why. Silence would read as "there
     * was nothing more", which is the wrong impression for a forensic artifact.
     */
    fun redact(details: String): String {
        if (details.isBlank()) return details
        val kept = details.trim().split(' ')
            .filter { it.substringBefore('=') in EXPORTABLE_KEYS }
        return if (kept.isEmpty()) REDACTION_NOTE else kept.joinToString(" ") + " " + REDACTION_NOTE
    }
}
