package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.File

/**
 * Sprint 75 Task 11 — per-rule integration tests for the migrated correlation rules.
 *
 * Loads each of the four migrated correlation YAML files from res/raw/ end-to-end
 * through SigmaRuleParser.parseCorrelation + SigmaCorrelationEngine and asserts the
 * expected cluster output on synthetic event fixtures.
 *
 * Why not "behavioral equivalence" vs. the old CorrelationEngine.kt? The plan called
 * for a side-by-side diff, but it is not practical: the old engine consumes a
 * different event model (TimelineEvent + TimelineCategory enum) and uses a different
 * category vocabulary, so the comparison would be non-meaningful. Instead each rule
 * is pinned to a fixture that exercises parser + evaluator end-to-end, which is the
 * regression net we actually want before CorrelationEngine.kt is deleted in Task 12.
 *
 * Loads YAML by absolute path relative to the repo; these tests must run from the
 * repo root (which is how Gradle invokes :app:testDebugUnitTest).
 */
class CorrelationMigrationFixturesTest {

    private fun loadYaml(filename: String): String {
        // Try relative from current working dir first (Gradle runs from app/ or repo root)
        val candidates = listOf(
            File("app/src/main/res/raw/$filename"),
            File("src/main/res/raw/$filename"),
            File("/home/yasir/AndroDR/app/src/main/res/raw/$filename")
        )
        return candidates.firstOrNull { it.exists() }?.readText()
            ?: error(
                "Could not locate $filename; tried: ${candidates.map { it.absolutePath }}"
            )
    }

    private fun event(
        id: Long,
        ts: Long,
        category: String,
        pkg: String = "com.test"
    ) = ForensicTimelineEvent(
        id = id,
        startTimestamp = ts,
        kind = "event",
        category = category,
        source = "test",
        description = "evt",
        packageName = pkg
    )

    // ---------- corr-001: install -> device admin grant (1h, temporal_ordered) ----------

    @Test
    fun `corr-001 install then admin fires on pair within window`() {
        val yaml = loadYaml("sigma_androdr_corr_001_install_then_admin.yml")
        val rule = SigmaRuleParser.parseCorrelation(yaml)
        assertEquals("androdr-corr-001", rule.id)
        assertEquals(CorrelationType.TEMPORAL_ORDERED, rule.type)

        val t0 = 1_000_000L
        val events = listOf(
            event(1, t0, "package_install"),
            event(2, t0 + 30 * 60_000L, "device_admin_grant")
        )
        val bindings = mapOf(
            1L to setOf("androdr-atom-package-install"),
            2L to setOf("androdr-atom-device-admin-grant")
        )

        val signals = SigmaCorrelationEngine().evaluate(listOf(rule), events, bindings)

        // NOTE: in production this rule will not fire until issue #79 lands
        // (no producer of category="device_admin_grant"). This test exercises
        // the loaded rule end-to-end with a synthetic admin-grant event.
        assertEquals(1, signals.size)
        val sig = signals[0]
        assertEquals("signal", sig.kind)
        assertEquals("correlation", sig.category)
        assertEquals("androdr-corr-001", sig.ruleId)
        assertEquals(t0, sig.startTimestamp)
        assertEquals(t0 + 30 * 60_000L, sig.endTimestamp)
    }

    // ---------- corr-002: install -> permission use (1h, temporal_ordered) ----------

    @Test
    fun `corr-002 install then permission fires on pair within window`() {
        val yaml = loadYaml("sigma_androdr_corr_002_install_then_permission.yml")
        val rule = SigmaRuleParser.parseCorrelation(yaml)
        assertEquals("androdr-corr-002", rule.id)
        assertEquals(CorrelationType.TEMPORAL_ORDERED, rule.type)
        assertEquals(3_600_000L, rule.timespanMs)

        val t0 = 2_000_000L
        val events = listOf(
            event(10, t0, "package_install"),
            event(11, t0 + 15 * 60_000L, "permission_use")
        )
        val bindings = mapOf(
            10L to setOf("androdr-atom-package-install"),
            11L to setOf("androdr-atom-permission-use")
        )

        val signals = SigmaCorrelationEngine().evaluate(listOf(rule), events, bindings)

        assertEquals(1, signals.size)
        assertEquals("androdr-corr-002", signals[0].ruleId)
        assertEquals(t0, signals[0].startTimestamp)
        assertEquals(t0 + 15 * 60_000L, signals[0].endTimestamp)
        assertEquals("correlation", signals[0].category)
    }

    // ---------- corr-003: permission use -> suspicious DNS (30m, temporal_ordered) ----------

    @Test
    fun `corr-003 permission then dns fires within 30m window`() {
        val yaml = loadYaml("sigma_androdr_corr_003_permission_then_c2.yml")
        val rule = SigmaRuleParser.parseCorrelation(yaml)
        assertEquals("androdr-corr-003", rule.id)
        assertEquals(CorrelationType.TEMPORAL_ORDERED, rule.type)
        assertEquals(30 * 60_000L, rule.timespanMs)

        val t0 = 3_000_000L
        val events = listOf(
            event(20, t0, "permission_use"),
            event(21, t0 + 10 * 60_000L, "dns_query")
        )
        val bindings = mapOf(
            20L to setOf("androdr-atom-permission-use"),
            21L to setOf("androdr-atom-dns-lookup")
        )

        val signals = SigmaCorrelationEngine().evaluate(listOf(rule), events, bindings)

        assertEquals(1, signals.size)
        assertEquals("androdr-corr-003", signals[0].ruleId)
        assertEquals(t0, signals[0].startTimestamp)
        assertEquals(t0 + 10 * 60_000L, signals[0].endTimestamp)
    }

    @Test
    fun `corr-003 does not fire when dns is outside 30m window`() {
        val yaml = loadYaml("sigma_androdr_corr_003_permission_then_c2.yml")
        val rule = SigmaRuleParser.parseCorrelation(yaml)

        val t0 = 3_000_000L
        val events = listOf(
            event(20, t0, "permission_use"),
            event(21, t0 + 31 * 60_000L, "dns_query")
        )
        val bindings = mapOf(
            20L to setOf("androdr-atom-permission-use"),
            21L to setOf("androdr-atom-dns-lookup")
        )

        val signals = SigmaCorrelationEngine().evaluate(listOf(rule), events, bindings)
        assertTrue("should not fire outside window", signals.isEmpty())
    }

    // ---------- corr-004: surveillance burst (event_count gte 3, 5m) ----------

    @Test
    fun `corr-004 surveillance burst fires on 3 permission uses within 5m`() {
        val yaml = loadYaml("sigma_androdr_corr_004_surveillance_burst.yml")
        val rule = SigmaRuleParser.parseCorrelation(yaml)
        assertEquals("androdr-corr-004", rule.id)
        assertEquals(CorrelationType.EVENT_COUNT, rule.type)
        assertEquals(3, rule.minEvents)
        assertEquals(5 * 60_000L, rule.timespanMs)

        val t0 = 4_000_000L
        val events = listOf(
            event(30, t0, "permission_use"),
            event(31, t0 + 60_000L, "permission_use"),
            event(32, t0 + 2 * 60_000L, "permission_use")
        )
        val bindings = mapOf(
            30L to setOf("androdr-atom-permission-use"),
            31L to setOf("androdr-atom-permission-use"),
            32L to setOf("androdr-atom-permission-use")
        )

        val signals = SigmaCorrelationEngine().evaluate(listOf(rule), events, bindings)

        assertEquals(1, signals.size)
        val sig = signals[0]
        assertEquals("androdr-corr-004", sig.ruleId)
        assertEquals("signal", sig.kind)
        assertEquals("correlation", sig.category)
        assertEquals(t0, sig.startTimestamp)
        assertEquals(t0 + 2 * 60_000L, sig.endTimestamp)
        assertTrue(sig.details.contains("\"member_event_ids\":\"30,31,32\""))
    }

    @Test
    fun `corr-004 does not fire with only 2 permission uses`() {
        val yaml = loadYaml("sigma_androdr_corr_004_surveillance_burst.yml")
        val rule = SigmaRuleParser.parseCorrelation(yaml)

        val t0 = 4_000_000L
        val events = listOf(
            event(30, t0, "permission_use"),
            event(31, t0 + 60_000L, "permission_use")
        )
        val bindings = mapOf(
            30L to setOf("androdr-atom-permission-use"),
            31L to setOf("androdr-atom-permission-use")
        )

        val signals = SigmaCorrelationEngine().evaluate(listOf(rule), events, bindings)
        assertTrue("should not fire below gte:3 threshold", signals.isEmpty())
    }
}
