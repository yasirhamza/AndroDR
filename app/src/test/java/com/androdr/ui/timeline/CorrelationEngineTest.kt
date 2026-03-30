package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CorrelationEngineTest {

    private val engine = CorrelationEngine()

    private fun event(
        id: Long, timestamp: Long, packageName: String,
        category: String, description: String = "test",
        correlationId: String = "", iocIndicator: String = ""
    ) = ForensicTimelineEvent(
        id = id, timestamp = timestamp, source = "test",
        category = category, description = description,
        severity = "HIGH", packageName = packageName,
        correlationId = correlationId, iocIndicator = iocIndicator
    )

    @Test
    fun `install-then-admin pattern detected regardless of time gap`() {
        val events = listOf(
            event(1, 1000000, "com.evil", "app_risk", "Sideloaded Application"),
            event(2, 9999999, "com.evil", "app_risk", "Device Admin Abuse")
        )
        val (clusters, standalone) = engine.partition(events)
        assertEquals(1, clusters.size)
        assertEquals(CorrelationPattern.INSTALL_THEN_ADMIN, clusters[0].pattern)
    }

    @Test
    fun `permission-then-C2 within 30 min detected`() {
        val events = listOf(
            event(1, 1000000, "com.spy", "permission_use", "used CAMERA"),
            event(2, 1500000, "com.spy", "ioc_match", "C2 domain", iocIndicator = "evil.com")
        )
        val (clusters, _) = engine.partition(events)
        assertEquals(1, clusters.size)
        assertEquals(CorrelationPattern.PERMISSION_THEN_C2, clusters[0].pattern)
    }

    @Test
    fun `multi-permission burst 3+ within 5 min detected`() {
        val events = listOf(
            event(1, 1000000, "com.spy", "permission_use", "CAMERA"),
            event(2, 1060000, "com.spy", "permission_use", "RECORD_AUDIO"),
            event(3, 1120000, "com.spy", "permission_use", "READ_SMS")
        )
        val (clusters, _) = engine.partition(events)
        assertEquals(1, clusters.size)
        assertEquals(CorrelationPattern.MULTI_PERMISSION_BURST, clusters[0].pattern)
    }

    @Test
    fun `install-then-permission within 1 hour detected`() {
        val events = listOf(
            event(1, 1000000, "com.app", "package_install", "installed"),
            event(2, 2000000, "com.app", "permission_use", "used CAMERA") // 17 min later
        )
        val (clusters, _) = engine.partition(events)
        assertEquals(1, clusters.size)
        assertEquals(CorrelationPattern.INSTALL_THEN_PERMISSION, clusters[0].pattern)
    }

    @Test
    fun `generic fallback clusters different categories within 30 min`() {
        val events = listOf(
            event(1, 1000000, "com.app", "app_foreground"),
            event(2, 1060000, "com.app", "app_risk")
        )
        val (clusters, _) = engine.partition(events)
        assertEquals(1, clusters.size)
        assertEquals(CorrelationPattern.GENERIC_TEMPORAL, clusters[0].pattern)
    }

    @Test
    fun `pre-linked correlationId groups override everything`() {
        val events = listOf(
            event(1, 1000000, "com.a", "install", correlationId = "abc"),
            event(2, 9999999, "com.b", "risk", correlationId = "abc")
        )
        val (clusters, _) = engine.partition(events)
        assertEquals(1, clusters.size)
        assertEquals(CorrelationPattern.PRE_LINKED, clusters[0].pattern)
    }

    @Test
    fun `single event is standalone`() {
        val events = listOf(event(1, 1000000, "com.solo", "risk"))
        val (clusters, standalone) = engine.partition(events)
        assertTrue(clusters.isEmpty())
        assertEquals(1, standalone.size)
    }

    @Test
    fun `empty list produces empty results`() {
        val (clusters, standalone) = engine.partition(emptyList())
        assertTrue(clusters.isEmpty())
        assertTrue(standalone.isEmpty())
    }
}
