package com.androdr.cellular

import com.androdr.data.model.SimContext

/**
 * What the SIM says the home network is: the operator code and the service
 * provider name it was provisioned with.
 *
 * This is the sturdier side of an operator comparison. The serving cell's
 * operator name is broadcast by the network — attacker-chosen when the
 * network is a rogue base station — while the SIM's was written at
 * provisioning and cannot be changed over the air. The 0.9.0.638 report
 * showed the existing name rules (androdr-105/106) matching the serving
 * name against a pattern; comparing it against the SIM needs no pattern.
 *
 * MCC/MNC here come from `getSimOperator()`, which is not a location: it
 * names the subscriber's home operator, the same fact the device publishes
 * in every ePDG lookup (`epdg.epc.mnc001.mcc427...`).
 */
data class SimIdentity(
    val mcc: String?,
    val mnc: String?,
    /** Service provider name, or null when the SIM carries none. */
    val operatorName: String?,
) {

    /**
     * Compares the SIM against the serving cell's identity.
     *
     * The MNC is compared numerically because the two sides may pad it
     * differently ("01" from the network, "001" from the SIM record). That
     * conflates the theoretical "01" ≠ "001" case; a mismatch detector
     * prefers that to a false alarm on every device with a padded SIM.
     *
     * The name comparison is containment either way on the letters and
     * digits alone, case-folded — the network's long name is often the
     * SIM's name plus a suffix ("Ooredoo" against "Ooredoo Qatar"), and the
     * two records space and punctuate differently ("Ooredoo_Qatar"). Null
     * when no comparable name exists on either side: an absent name is not
     * a mismatching one, and a name that is all digits (some networks
     * broadcast the PLMN code as their "name") or shorter than three
     * characters is too little to contain, or be contained by, anything
     * meaningfully — "O" is in every operator.
     */
    fun compare(
        servingMcc: String?,
        servingMnc: String?,
        servingAlphaLong: String?,
        servingAlphaShort: String?,
    ): SimContext = SimContext(
        mcc = mcc,
        mnc = mnc,
        operatorName = operatorName,
        plmnMatchesSim = plmnMatches(servingMcc, servingMnc),
        operatorNameMatchesSim = nameMatches(servingAlphaLong, servingAlphaShort),
    )

    private fun plmnMatches(servingMcc: String?, servingMnc: String?): Boolean? {
        val simMnc = mnc?.toIntOrNull()
        val cellMnc = servingMnc?.toIntOrNull()
        if (mcc.isNullOrBlank() || servingMcc.isNullOrBlank() || simMnc == null || cellMnc == null) return null
        return mcc == servingMcc && simMnc == cellMnc
    }

    private fun nameMatches(alphaLong: String?, alphaShort: String?): Boolean? {
        val spn = comparable(operatorName) ?: return null
        val names = listOfNotNull(alphaLong, alphaShort).mapNotNull(::comparable)
        if (names.isEmpty()) return null
        return names.any { it.contains(spn) || spn.contains(it) }
    }

    private fun comparable(name: String?): String? = name
        ?.lowercase()
        ?.filter(Char::isLetterOrDigit)
        ?.takeIf { it.length >= MIN_NAME_LENGTH && !it.all(Char::isDigit) }

    companion object {
        private const val MCC_DIGITS = 3
        private const val MIN_NAME_LENGTH = 3

        /**
         * Splits a `getSimOperator()` value ("42701", "310260") into MCC and
         * MNC; null for anything that is not at least an MCC plus one digit.
         */
        fun fromSimOperator(simOperator: String?, operatorName: String?): SimIdentity? {
            val code = simOperator?.trim().orEmpty()
            if (code.length <= MCC_DIGITS || !code.all(Char::isDigit)) return null
            return SimIdentity(
                mcc = code.substring(0, MCC_DIGITS),
                mnc = code.substring(MCC_DIGITS),
                operatorName = operatorName?.trim()?.takeIf { it.isNotEmpty() },
            )
        }
    }
}
