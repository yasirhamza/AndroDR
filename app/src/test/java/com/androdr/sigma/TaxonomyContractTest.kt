package com.androdr.sigma

import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * [TaxonomyContract] is the one Kotlin mirror of the taxonomy facts the store
 * needs (spec §4.3). This is its single cross-check, in both directions, plus
 * gate X1: the computed-column contract hash.
 */
class TaxonomyContractTest {

    private fun taxonomy(): Map<String, TestRuleRepo.TaxonomyService> {
        val taxonomy = TestRuleRepo.loadTaxonomy()
        assumeTrue("Skipping: submodule not initialized.", taxonomy != null)
        return taxonomy!!
    }

    @Test
    fun `contract services equal taxonomy services in both directions`() {
        val taxonomy = taxonomy()
        assertEquals(
            "Services missing from TaxonomyContract",
            emptySet<String>(), taxonomy.keys - TaxonomyContract.services,
        )
        assertEquals(
            "TaxonomyContract services absent from the taxonomy",
            emptySet<String>(), TaxonomyContract.services - taxonomy.keys,
        )
    }

    @Test
    fun `every contract accessor equals the taxonomy`() {
        val failures = mutableListOf<String>()
        for ((service, entry) in taxonomy()) {
            fun check(what: String, expected: Any?, actual: Any?) {
                if (expected != actual) failures += "$service.$what: taxonomy=$expected contract=$actual"
            }
            check("event_time_field", entry.eventTimeField, TaxonomyContract.eventTimeField(service))
            check("time_precision_field", entry.timePrecisionField, TaxonomyContract.precisionField(service))
            check("key_fields", entry.keyFields, TaxonomyContract.keyFields(service))
            check("package_field", entry.packageField, TaxonomyContract.packageField(service))
            check("field order", entry.descriptions.keys.toList(), TaxonomyContract.fieldOrder(service))
            for ((field, description) in entry.descriptions) {
                check("$field.description", description, TaxonomyContract.description(service, field))
            }
        }
        assertTrue(
            "TaxonomyContract drifted from logsource-taxonomy.yml:\n" +
                failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }

    @Test
    fun `event services are exactly the services declaring an event time field`() {
        val expected = taxonomy().filterValues { it.eventTimeField != null }.keys
        assertEquals(expected, TaxonomyContract.eventServices)
    }

    @Test
    fun `unknown service or field has no contract facts`() {
        assertNull(TaxonomyContract.eventTimeField("no_such_service"))
        assertEquals(emptyList<String>(), TaxonomyContract.keyFields("no_such_service"))
        assertNull(TaxonomyContract.description("dns_monitor", "no_such_field"))
    }

    @Test
    fun `a live app-ops map is a snapshot`() {
        val live = AppOpsTelemetry(
            packageName = "com.example", operation = "android:camera", lastAccessTime = 1_787_000_000_000L,
            lastRejectTime = 0L, accessCount = 3, isSystemApp = false, source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap()
        assertNull(TaxonomyContract.eventTimeOf("appops_audit", live))
    }

    @Test
    fun `a bug-report app-ops map with event_time_ms is an event`() {
        val bugReport = mapOf(
            "package_name" to "com.example", "operation" to "android:camera",
            "source" to "bugreport_import", "event_time_ms" to 1_787_220_000_000L,
        )
        assertEquals(1_787_220_000_000L, TaxonomyContract.eventTimeOf("appops_audit", bugReport))
        // The module writes 0 when the dumpsys line had no parseable time.
        assertNull(TaxonomyContract.eventTimeOf("appops_audit", bugReport + ("event_time_ms" to 0L)))
    }

    @Test
    fun `db_info has no event time field`() {
        assertNull(TaxonomyContract.eventTimeField("db_info"))
        val record = mapOf("file_path" to "/data/x.db", "observation_timestamp" to 1_787_000_000_000L)
        assertNull(TaxonomyContract.eventTimeOf("db_info", record))
    }

    @Test
    fun `battery daily time is day precision and everything else exact`() {
        val day = mapOf("timestamp" to 1_787_184_000_000L, "timestamp_precision" to "day")
        assertEquals(TimePrecision.DAY, TaxonomyContract.precisionOf("battery_daily", day))
        assertEquals(TimePrecision.EXACT, TaxonomyContract.precisionOf("battery_daily", mapOf("timestamp" to 1L)))
        assertEquals(TimePrecision.EXACT, TaxonomyContract.precisionOf("dns_monitor", day))
    }

    @Test
    fun `corpus has a record for every event service`() {
        val corpusServices = ContractCorpus.records().map { it.first }.toSet()
        assertEquals(
            "Every event service needs a corpus record, or X1 does not pin its outputs",
            emptySet<String>(), TaxonomyContract.eventServices - corpusServices,
        )
    }

    /**
     * X1. The computed columns (subjectKey, category, packageName, timePrecision,
     * eventTime) are stored. Changing the contract table, [TimelineCategories] or
     * the precision logic changes what a recompute would write, so it must come
     * with a recompute migration and a new [TaxonomyContract.CONTRACT_SCHEMA_VERSION].
     */
    @Test
    fun `contract hash equals the value pinned for CONTRACT_SCHEMA_VERSION`() {
        val pinned = PINNED_CONTRACT_HASHES[TaxonomyContract.CONTRACT_SCHEMA_VERSION]
        val actual = TaxonomyContract.corpusHash(ContractCorpus.records())
        assertEquals(
            "Computed-column contract changed (actual $actual): recompute migration + bump " +
                "CONTRACT_SCHEMA_VERSION, then pin the new hash under the new version.",
            pinned, actual,
        )
    }

    private companion object {
        /** Schema version that last recomputed the computed columns -> its contract hash. */
        val PINNED_CONTRACT_HASHES = mapOf(
            19 to "a18120eb79c0e201886766cace4a3b45f3b77cf0f403b0c777b64faa19b910a9",
        )
    }
}
