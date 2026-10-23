package com.androdr.sigma

import java.security.MessageDigest

/** How exact a record's event time is. Only [EXACT] facts become correlation atoms. */
enum class TimePrecision { EXACT, DAY }

/** One service's entry in [TAXONOMY_CONTRACT_TABLE]. */
internal data class ServiceContract(
    val eventTimeField: String? = null,
    val precisionField: String? = null,
    val keyFields: List<String> = emptyList(),
    val packageField: String? = null,
    /** Field name -> taxonomy description, in taxonomy order. */
    val fields: List<Pair<String, String?>>,
)

/**
 * The single Kotlin mirror of the taxonomy facts the telemetry store needs
 * (spec §4.3): event-time field, precision field, key fields, package field,
 * field order and descriptions. The data lives in [TAXONOMY_CONTRACT_TABLE];
 * TaxonomyContractTest checks it against `logsource-taxonomy.yml` in both
 * directions.
 *
 * A record is an **event record** iff its service declares an event-time
 * field and the record's value there is present and > 0 ([eventTimeOf]).
 */
object TaxonomyContract {

    /**
     * Schema version that last recomputed the stored computed columns
     * (subjectKey, category, packageName, timePrecision, eventTime). Any change
     * to [contractHash] or to [TimelineCategories] / [precisionOf] outputs needs
     * a recompute migration and a bump here (gate X1).
     */
    const val CONTRACT_SCHEMA_VERSION = 19

    private const val DAY_PRECISION = "day"

    private val table: Map<String, ServiceContract> = TAXONOMY_CONTRACT_TABLE

    /** Every taxonomy service. */
    val services: Set<String> = table.keys

    /** Services that declare an event-time field (their records can be events). */
    val eventServices: Set<String> = table.filterValues { it.eventTimeField != null }.keys

    /**
     * SHA-256 (hex) of the contract table's computed-column facts: per service,
     * event-time field, precision field, key fields and package field.
     * Descriptions and field order are display facts and stay out of it.
     */
    val contractHash: String = sha256(
        table.toSortedMap().entries.joinToString("\n") { (service, c) ->
            listOf(
                service,
                c.eventTimeField.orEmpty(),
                c.precisionField.orEmpty(),
                c.keyFields.joinToString(","),
                c.packageField.orEmpty(),
            ).joinToString("|")
        }
    )

    fun eventTimeField(service: String): String? = table[service]?.eventTimeField

    fun precisionField(service: String): String? = table[service]?.precisionField

    fun keyFields(service: String): List<String> = table[service]?.keyFields.orEmpty()

    fun packageField(service: String): String? = table[service]?.packageField

    fun fieldOrder(service: String): List<String> = table[service]?.fields?.map { it.first }.orEmpty()

    fun description(service: String, field: String): String? =
        table[service]?.fields?.firstOrNull { it.first == field }?.second

    /** The record's event time, or null when it is a snapshot (no field, absent, or <= 0). */
    fun eventTimeOf(service: String, fields: Map<String, Any?>): Long? {
        val field = eventTimeField(service) ?: return null
        return (fields[field] as? Number)?.toLong()?.takeIf { it > 0L }
    }

    /** [TimePrecision.DAY] when the service's precision field says `day`; otherwise exact. */
    fun precisionOf(service: String, fields: Map<String, Any?>): TimePrecision {
        val field = precisionField(service) ?: return TimePrecision.EXACT
        val value = fields[field]?.toString()
        return if (value.equals(DAY_PRECISION, ignoreCase = true)) TimePrecision.DAY else TimePrecision.EXACT
    }

    /**
     * [contractHash] folded with the computed outputs (category, precision,
     * event time) over [records], in order. Gate X1 pins this over the fixed
     * test corpus, so a change to the table, [TimelineCategories] or the
     * precision logic fails the build until a recompute migration exists.
     */
    fun corpusHash(records: List<Pair<String, Map<String, Any?>>>): String = sha256(
        contractHash + "\n" + records.joinToString("\n") { (service, fields) ->
            listOf(
                service,
                TimelineCategories.categoryOf(service, fields),
                precisionOf(service, fields).name,
                eventTimeOf(service, fields)?.toString().orEmpty(),
            ).joinToString("|")
        }
    )

    private fun sha256(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}
