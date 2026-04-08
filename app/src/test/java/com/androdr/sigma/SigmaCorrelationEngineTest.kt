package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.*
import org.junit.Test

class SigmaCorrelationEngineTest {

    private fun event(
        id: Long, ts: Long, category: String, pkg: String = "com.test"
    ) = ForensicTimelineEvent(
        id = id, startTimestamp = ts, kind = "event", category = category,
        source = "test", description = "evt", severity = "info", packageName = pkg
    )

    private val installRule = CorrelationRule(
        id = "test-install-then-admin",
        title = "T",
        type = CorrelationType.TEMPORAL_ORDERED,
        referencedRuleIds = listOf("atom-install", "atom-admin"),
        timespanMs = 3_600_000L,
        groupBy = listOf("package_name"),
        minEvents = 1,
        severity = "high",
        displayLabel = "Install then admin"
    )

    private val burstRule = CorrelationRule(
        id = "test-burst",
        title = "T",
        type = CorrelationType.EVENT_COUNT,
        referencedRuleIds = listOf("atom-perm"),
        timespanMs = 300_000L,
        groupBy = listOf("package_name"),
        minEvents = 3,
        severity = "high",
        displayLabel = "Burst"
    )

    private fun bindings(vararg pairs: Pair<Long, Set<String>>): Map<Long, Set<String>> = pairs.toMap()

    @Test
    fun `temporal_ordered fires when both events occur in order within window`() {
        val events = listOf(
            event(1, 1000, "package_install"),
            event(2, 2000, "device_admin_grant")
        )
        val binds = bindings(1L to setOf("atom-install"), 2L to setOf("atom-admin"))
        val signals = SigmaCorrelationEngine().evaluate(listOf(installRule), events, binds)
        assertEquals(1, signals.size)
        assertEquals("test-install-then-admin", signals[0].ruleId)
        assertEquals(1000L, signals[0].startTimestamp)
        assertEquals(2000L, signals[0].endTimestamp)
        assertEquals("signal", signals[0].kind)
        assertTrue(signals[0].details.contains("\"member_event_ids\":\"1,2\""))
    }

    @Test
    fun `temporal_ordered does not fire when order is reversed`() {
        val events = listOf(
            event(1, 1000, "device_admin_grant"),
            event(2, 2000, "package_install")
        )
        val binds = bindings(1L to setOf("atom-admin"), 2L to setOf("atom-install"))
        val signals = SigmaCorrelationEngine().evaluate(listOf(installRule), events, binds)
        assertTrue(signals.isEmpty())
    }

    @Test
    fun `temporal_ordered does not fire when window exceeded`() {
        val events = listOf(
            event(1, 1000, "package_install"),
            event(2, 1000 + 3_600_001L, "device_admin_grant")
        )
        val binds = bindings(1L to setOf("atom-install"), 2L to setOf("atom-admin"))
        val signals = SigmaCorrelationEngine().evaluate(listOf(installRule), events, binds)
        assertTrue(signals.isEmpty())
    }

    @Test
    fun `event_count fires when threshold met within window`() {
        val events = listOf(
            event(1, 1000, "permission_use"),
            event(2, 2000, "permission_use"),
            event(3, 3000, "permission_use")
        )
        val binds = bindings(
            1L to setOf("atom-perm"),
            2L to setOf("atom-perm"),
            3L to setOf("atom-perm")
        )
        val signals = SigmaCorrelationEngine().evaluate(listOf(burstRule), events, binds)
        assertEquals(1, signals.size)
        assertTrue(signals[0].details.contains("\"member_event_ids\":\"1,2,3\""))
    }

    @Test
    fun `event_count does not fire when below threshold`() {
        val events = listOf(
            event(1, 1000, "permission_use"),
            event(2, 2000, "permission_use")
        )
        val binds = bindings(1L to setOf("atom-perm"), 2L to setOf("atom-perm"))
        val signals = SigmaCorrelationEngine().evaluate(listOf(burstRule), events, binds)
        assertTrue(signals.isEmpty())
    }

    @Test
    fun `group-by isolates clusters per package`() {
        val events = listOf(
            event(1, 1000, "package_install", pkg = "com.a"),
            event(2, 2000, "device_admin_grant", pkg = "com.b")
        )
        val binds = bindings(1L to setOf("atom-install"), 2L to setOf("atom-admin"))
        val signals = SigmaCorrelationEngine().evaluate(listOf(installRule), events, binds)
        assertTrue("group-by package_name should prevent cross-package match", signals.isEmpty())
    }
}
