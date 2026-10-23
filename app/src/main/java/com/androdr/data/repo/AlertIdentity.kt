package com.androdr.data.repo

import com.androdr.data.store.HashKeys
import com.androdr.sigma.Evidence
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Alert identity (spec §5.4): the key every finding of one incident shares, so re-fires attach to
 * the alert the first one opened. The evidence discriminator is the evidence *type and matched
 * value* only — never IOC row ids or feed metadata (family, source, reference) — so it is stable
 * across an IOC re-sync. Correlation findings get no key: they are state findings.
 */
object AlertIdentity {
    /** A record finding: `h128("$ruleId|$factId|${evidence.type}|${evidence.matchedValue}")`. */
    fun recordKey(ruleId: String, factId: Long, evidence: Evidence): ByteArray =
        recordKey(ruleId, factId, Discriminator.of(evidence))

    /**
     * An evaluate-only finding with no stored fact:
     * `h128("$ruleId|nofact|${evidence.type}|${evidence.matchedValue}|${eventTime ?: "$scanId|$ordinal"}")`,
     * so unrelated hits without an event time never collapse into one alert.
     */
    fun noFactKey(ruleId: String, evidence: Evidence, eventTime: Long?, scanId: Long, ordinal: Int): ByteArray =
        noFactKey(ruleId, Discriminator.of(evidence), eventTime, scanId, ordinal)

    internal fun recordKey(ruleId: String, factId: Long, d: Discriminator): ByteArray =
        HashKeys.h128("$ruleId|$factId|${d.type}|${d.matchedValue}")

    internal fun noFactKey(ruleId: String, d: Discriminator, eventTime: Long?, scanId: Long, ordinal: Int): ByteArray =
        HashKeys.h128("$ruleId|nofact|${d.type}|${d.matchedValue}|${eventTime ?: "$scanId|$ordinal"}")

    /** Evidence type (its serial name) and matched value. */
    data class Discriminator(val type: String, val matchedValue: String) {
        companion object {
            fun of(evidence: Evidence): Discriminator = when (evidence) {
                Evidence.None -> Discriminator(NONE, "")
                is Evidence.IocMatch -> Discriminator(IOC_MATCH, evidence.matchedIndicator)
                is Evidence.CveList ->
                    Discriminator(CVE_LIST, evidence.cves.map { it.cveId }.sorted().joinToString(","))
                is Evidence.PermissionCluster ->
                    Discriminator(PERMISSION_CLUSTER, evidence.permissions.sorted().joinToString(","))
            }

            /**
             * The same discriminator read from a stored finding's `evidence` JSON (class
             * discriminator `type`; absent evidence is [Evidence.None]). The migration uses it, so
             * it never depends on today's model classes; a cross-check test pins it to [of].
             */
            fun ofJson(evidence: JsonObject?): Discriminator {
                val type = evidence?.str("type") ?: NONE
                val value = when (type) {
                    IOC_MATCH -> evidence?.str("matchedIndicator").orEmpty()
                    CVE_LIST -> (evidence?.get("cves") as? JsonArray).orEmpty()
                        .mapNotNull { (it as? JsonObject)?.str("cveId") }.sorted().joinToString(",")
                    PERMISSION_CLUSTER -> (evidence?.get("permissions") as? JsonArray).orEmpty()
                        .mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.sorted().joinToString(",")
                    else -> ""
                }
                return Discriminator(type, value)
            }

            private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull

            private const val NONE = "none"
            private const val IOC_MATCH = "ioc_match"
            private const val CVE_LIST = "cve_list"
            private const val PERMISSION_CLUSTER = "permission_cluster"
        }
    }
}
