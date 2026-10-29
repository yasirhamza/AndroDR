package com.androdr.data.repo

import com.androdr.data.db.Converters
import com.androdr.data.db.FindingKinds
import com.androdr.data.db.FrozenRuleServices
import com.androdr.data.model.FindingKind
import com.androdr.data.store.HashKeys
import com.androdr.sigma.CveEvidence
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.TaxonomyContract
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Alert identity (spec §5.4) and the shared no-fact kind rule. */
class AlertIdentityTest {

    private val ioc = Evidence.IocMatch("evil.example", "domain", "feed-a", family = "Pegasus", reference = "r1")

    @Test
    fun `record and no-fact keys are the brief's exact formulas`() {
        assertArrayEquals(HashKeys.h128("androdr-003|42|ioc_match|evil.example"),
            AlertIdentity.recordKey("androdr-003", 42L, ioc))
        assertArrayEquals(HashKeys.h128("androdr-003|nofact|ioc_match|evil.example|1700"),
            AlertIdentity.noFactKey("androdr-003", ioc, 1700L, 9L, 3))
        assertArrayEquals(HashKeys.h128("androdr-003|nofact|ioc_match|evil.example|9|3"),
            AlertIdentity.noFactKey("androdr-003", ioc, null, 9L, 3))
        assertArrayEquals(HashKeys.h128("r|7|none|"), AlertIdentity.recordKey("r", 7L, Evidence.None))
    }

    @Test
    fun `the evidence discriminator is unchanged by an IOC re-sync`() {
        val resynced = ioc.copy(source = "feed-b", family = "Graphite", category = "x", campaign = "c",
            reference = "r2", observedAt = 99L)
        assertArrayEquals(AlertIdentity.recordKey("androdr-003", 42L, ioc),
            AlertIdentity.recordKey("androdr-003", 42L, resynced))
    }

    @Test
    fun `two evidence results on one record give two keys`() {
        val other = ioc.copy(matchedIndicator = "other.example")
        assertFalse(AlertIdentity.recordKey("r", 1L, ioc).contentEquals(AlertIdentity.recordKey("r", 1L, other)))
    }

    @Test
    fun `the JSON discriminator equals the model discriminator for every evidence type`() {
        val all = listOf(
            Evidence.None, ioc,
            Evidence.CveList(listOf(cve("CVE-2"), cve("CVE-1")), "2026-01-01", 1),
            Evidence.PermissionCluster(listOf("b", "a"), 2),
        )
        for (e in all) {
            val stored = Converters.fromFindingList(listOf(finding(e)))
            val evidence = (Json.parseToJsonElement(stored) as JsonArray).single().let { it as JsonObject }["evidence"]
            assertEquals("$e", AlertIdentity.Discriminator.of(e),
                AlertIdentity.Discriminator.ofJson(evidence as? JsonObject))
        }
    }

    @Test
    fun `no-fact kind - always-event services and a positive event time are alerts`() {
        assertEquals(FindingKind.ALERT, FindingKinds.noFact("dns_monitor", "timestamp", emptyMap()))
        assertEquals(FindingKind.ALERT, FindingKinds.noFact("security_log", null, emptyMap()))
        assertEquals(FindingKind.ALERT,
            FindingKinds.noFact("appops_audit", "event_time_ms", mapOf("event_time_ms" to "5")))
        assertEquals(FindingKind.STATE,
            FindingKinds.noFact("appops_audit", "event_time_ms", mapOf("event_time_ms" to "0")))
        assertEquals(FindingKind.STATE, FindingKinds.noFact("app_scanner", null, mapOf("timestamp" to "5")))
        assertEquals(FindingKind.STATE, FindingKinds.noFact(null, null, emptyMap()))
    }

    @Test
    fun `every frozen service exists in the taxonomy`() {
        val known = com.androdr.sigma.TAXONOMY_CONTRACT_TABLE.keys
        for (s in FrozenRuleServices.EVENT_TIME_FIELD_BY_SERVICE.keys) {
            assertTrue(s, s in TaxonomyContract.eventServices)
        }
        for (s in FrozenRuleServices.SERVICE_BY_RULE.values) assertTrue(s, s in known)
        assertTrue(FindingKinds.ALWAYS_EVENT.all { it in FrozenRuleServices.EVENT_TIME_FIELD_BY_SERVICE })
    }

    private fun cve(id: String) = CveEvidence(id, "", "high", "", emptyList(), "")

    private fun finding(e: Evidence) =
        Finding(ruleId = "r", title = "t", level = "high", category = FindingCategory.APP_RISK, evidence = e)
}
