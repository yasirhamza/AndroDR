package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CorrelationEngineTest {

    private val engine = CorrelationEngine()

    private fun event(
        id: Long, timestamp: Long, packageName: String,
        category: String, correlationId: String = ""
    ) = ForensicTimelineEvent(
        id = id, timestamp = timestamp, source = "test",
        category = category, description = "test",
        severity = "HIGH", packageName = packageName,
        correlationId = correlationId
    )

    @Test
    fun `clusters events from same package within 30 min with different categories`() {
        val events = listOf(
            event(1, 1000000, "com.evil.spy", "package_install"),
            event(2, 1060000, "com.evil.spy", "app_risk"),       // 1 min later
            event(3, 1120000, "com.evil.spy", "permission_use"), // 2 min later
            event(4, 9000000, "com.legit.app", "app_foreground") // standalone
        )
        val (clusters, standalone) = engine.partition(events)
        assertEquals(1, clusters.size)
        assertEquals(3, clusters[0].size)
        assertEquals(1, standalone.size)
        assertEquals("com.legit.app", standalone[0].packageName)
    }

    @Test
    fun `does not cluster events with same category`() {
        val events = listOf(
            event(1, 1000000, "com.app", "app_foreground"),
            event(2, 1060000, "com.app", "app_foreground"),
            event(3, 1120000, "com.app", "app_foreground")
        )
        val (clusters, standalone) = engine.partition(events)
        assertEquals(0, clusters.size)
        assertEquals(3, standalone.size)
    }

    @Test
    fun `splits events beyond 30 min gap into separate clusters`() {
        val events = listOf(
            event(1, 1000000, "com.evil", "package_install"),
            event(2, 1060000, "com.evil", "app_risk"),
            // 45 min gap
            event(3, 3760000, "com.evil", "permission_use"),
            event(4, 3820000, "com.evil", "dns_query")
        )
        val (clusters, standalone) = engine.partition(events)
        assertEquals(2, clusters.size)
    }

    @Test
    fun `pre-linked correlationId groups override time window`() {
        val events = listOf(
            event(1, 1000000, "com.a", "install", correlationId = "abc"),
            event(2, 9999999, "com.b", "risk", correlationId = "abc"), // different pkg, far apart
            event(3, 5000000, "com.c", "other")
        )
        val (clusters, standalone) = engine.partition(events)
        assertEquals(1, clusters.size)
        assertEquals(2, clusters[0].size)
        assertTrue(clusters[0].all { it.correlationId == "abc" })
        assertEquals(1, standalone.size)
    }

    @Test
    fun `single event is standalone`() {
        val events = listOf(event(1, 1000000, "com.solo", "risk"))
        val (clusters, standalone) = engine.partition(events)
        assertEquals(0, clusters.size)
        assertEquals(1, standalone.size)
    }

    @Test
    fun `empty list produces empty results`() {
        val (clusters, standalone) = engine.partition(emptyList())
        assertTrue(clusters.isEmpty())
        assertTrue(standalone.isEmpty())
    }
}
