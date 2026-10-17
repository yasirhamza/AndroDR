package com.androdr.ioc

/**
 * Campaign keys for MVT collections, matched exactly on (collection name, STIX URL)
 * from MVT's indicators.yaml. Compiled on purpose (spec §3.1a): only these exact
 * collections can mark a campaign, never a renamed, look-alike or generic source.
 */
object MvtCampaigns {
    private val EXACT: Map<Pair<String, String>, String> = mapOf(
        ("NSO Group Pegasus Indicators of Compromise" to
            "https://raw.githubusercontent.com/AmnestyTech/investigations/" +
            "master/2021-07-18_nso/pegasus.stix2") to "pegasus",
        ("Predator Spyware Indicators of Compromise" to
            "https://raw.githubusercontent.com/mvt-project/mvt-indicators/" +
            "main/intellexa_predator/predator.stix2") to "predator",
    )
    fun keyFor(name: String, url: String): String? = EXACT[name to url]
    fun allKeys(): Set<String> = EXACT.values.toSet()
    /**
     * Used by the app's cross-check unit test (MvtCampaignsTest) against the rules
     * repo's `validation/mvt-campaign-map.json`.
     */
    fun entries(): Map<Pair<String, String>, String> = EXACT
}
