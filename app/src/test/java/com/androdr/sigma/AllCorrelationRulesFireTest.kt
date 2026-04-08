package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * End-to-end "fire everything" test for the four migrated correlation rules.
 *
 * Loads all four YAML files (corr-001 through corr-004), then builds one synthetic
 * event timeline that satisfies every rule's preconditions. Runs the parser and
 * evaluator end-to-end and prints the resulting signal rows.
 *
 * Useful for inspecting what a correlation signal actually looks like coming out
 * of SigmaCorrelationEngine — the per-rule fixture tests in
 * CorrelationMigrationFixturesTest only check one rule at a time.
 *
 * The fixture is intentionally small but exercises every shape:
 *  - corr-001 (temporal_ordered): install -> device_admin_grant on pkg A
 *  - corr-002 (temporal_ordered): install -> permission_use on pkg B
 *  - corr-003 (temporal_ordered): permission_use -> ioc_match on pkg C
 *  - corr-004 (event_count): 3 permission_use events on pkg D within 5 minutes
 */
class AllCorrelationRulesFireTest {

    private val ruleFiles = listOf(
        "sigma_androdr_corr_001_install_then_admin.yml",
        "sigma_androdr_corr_002_install_then_permission.yml",
        "sigma_androdr_corr_003_permission_then_c2.yml",
        "sigma_androdr_corr_004_surveillance_burst.yml"
    )

    private val atomFor = mapOf(
        "package_install"    to "androdr-atom-package-install",
        "device_admin_grant" to "androdr-atom-device-admin-grant",
        "permission_use"     to "androdr-atom-permission-use",
        "ioc_match"          to "androdr-atom-dns-lookup"
    )

    @Test
    fun `all four migrated correlation rules fire on a single synthetic timeline`() {
        // 1. Load + parse every rule.
        val rules = ruleFiles.map { SigmaRuleParser.parseCorrelation(loadYaml(it)) }
        assertEquals("expected 4 correlation rules loaded", 4, rules.size)
        rules.forEach { println("loaded rule: ${it.id} type=${it.type} timespan=${it.timespanMs}ms") }

        // 2. Build a synthetic timeline that satisfies every rule simultaneously.
        // Each rule uses group-by package_name, so giving each rule its own
        // package keeps the chains independent and easy to read in the output.
        val t0 = 1_700_000_000_000L  // arbitrary epoch ms anchor
        val min = 60_000L

        val events = mutableListOf<ForensicTimelineEvent>()
        var nextId = 1L
        fun add(category: String, ts: Long, pkg: String): ForensicTimelineEvent {
            val e = event(nextId++, ts, category, pkg)
            events += e
            return e
        }

        // corr-001: install -> admin (1h window) on com.installthenadmin
        add("package_install",     t0,           "com.installthenadmin")
        add("device_admin_grant",  t0 + 5 * min, "com.installthenadmin")

        // corr-002: install -> permission_use (1h window) on com.installthenperm
        add("package_install",     t0 + 10 * min, "com.installthenperm")
        add("permission_use",      t0 + 12 * min, "com.installthenperm")

        // corr-003: permission_use -> ioc_match (30m window) on com.permthenioc
        add("permission_use",      t0 + 20 * min, "com.permthenioc")
        add("ioc_match",           t0 + 22 * min, "com.permthenioc")

        // corr-004: 3 permission_use events within 5 minutes on com.burst
        add("permission_use",      t0 + 30 * min,         "com.burst")
        add("permission_use",      t0 + 30 * min + 30_000, "com.burst")
        add("permission_use",      t0 + 30 * min + 60_000, "com.burst")

        // 3. Compute bindings (eventId -> set of atom rule ids that match it).
        // SigmaRuleEngine.computeAtomBindings does this in production by reading
        // each detection rule's selection.category. The test version is the same
        // mapping table, hand-built so the test is independent of engine state.
        val bindings: Map<Long, Set<String>> = events.associate { ev ->
            val atomId = atomFor[ev.category]
            ev.id to (if (atomId != null) setOf(atomId) else emptySet())
        }

        // 4. Run the engine.
        val engine = SigmaCorrelationEngine()
        val signals = engine.evaluate(rules, events, bindings)

        // 5. Print the output for human inspection (visible in test output).
        println()
        println("=== ${signals.size} SIGNAL(S) FIRED ===")
        signals.forEachIndexed { i, sig ->
            println("[${i + 1}] ruleId=${sig.ruleId}")
            println("    package=${sig.packageName}")
            println("    severity=${sig.severity}")
            println("    description=${sig.description}")
            println("    startTimestamp=${sig.startTimestamp}")
            println("    endTimestamp=${sig.endTimestamp}")
            println("    kind=${sig.kind}")
            println("    category=${sig.category}")
            println("    source=${sig.source}")
            println("    correlationId=${sig.correlationId}")
            println("    details=${sig.details}")
            println()
        }

        // 6. Assert each rule produced exactly one signal.
        assertEquals(
            "expected one signal per rule (4 rules -> 4 signals); got: ${signals.map { it.ruleId }}",
            4,
            signals.size
        )

        val byRule = signals.associateBy { it.ruleId }
        listOf("androdr-corr-001", "androdr-corr-002", "androdr-corr-003", "androdr-corr-004")
            .forEach { id -> assertNotNull("rule $id did not fire", byRule[id]) }

        // Spot-check the corr-001 signal carries both member event ids in its details JSON.
        val corr001 = byRule.getValue("androdr-corr-001")
        assertEquals("signal", corr001.kind)
        assertEquals("correlation", corr001.category)
        assertEquals("com.installthenadmin", corr001.packageName)
        assertEquals(t0, corr001.startTimestamp)
        assertEquals(t0 + 5 * min, corr001.endTimestamp)
        assertTrue(
            "corr-001 details should encode both member event ids",
            corr001.details.contains("\"member_event_ids\":\"1,2\"")
        )

        // Spot-check the corr-004 burst signal carries 3 member ids.
        val corr004 = byRule.getValue("androdr-corr-004")
        assertEquals("com.burst", corr004.packageName)
        assertTrue(
            "corr-004 details should list 3 member ids",
            corr004.details.contains("\"member_event_ids\":\"7,8,9\"")
        )
    }

    private fun event(id: Long, ts: Long, category: String, pkg: String) =
        ForensicTimelineEvent(
            id = id,
            startTimestamp = ts,
            kind = "event",
            category = category,
            source = "test",
            description = "evt",
            severity = "info",
            packageName = pkg
        )

    private fun loadYaml(filename: String): String {
        val candidates = listOf(
            File("app/src/main/res/raw/$filename"),
            File("src/main/res/raw/$filename"),
            File("/home/yasir/AndroDR/app/src/main/res/raw/$filename")
        )
        return candidates.firstOrNull { it.exists() }?.readText()
            ?: throw IllegalStateException(
                "Could not locate $filename; tried: ${candidates.map { it.absolutePath }}"
            )
    }
}
