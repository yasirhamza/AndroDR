package com.androdr.data.store

import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.TaxonomyContract
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** `res/raw/event_display.yml`: one summary template per event service, naming only real fields. */
class EventDisplayTest {
    private val display = EventDisplay.parse(rawFile("event_display.yml").readText())

    @Test
    fun `every event service has an EventDisplay template`() {
        assertEquals(emptySet<String>(), TaxonomyContract.eventServices - display.services)
    }

    @Test
    fun `templates name only fields of their service`() {
        for (service in display.services) {
            val fields = TaxonomyContract.fieldOrder(service).toSet()
            assertTrue("unknown service $service", service in TaxonomyContract.services)
            val unknown = display.placeholders(service) - fields
            assertTrue("$service template names unknown fields $unknown", unknown.isEmpty())
            assertTrue("$service template has no placeholder", display.placeholders(service).isNotEmpty())
        }
    }

    @Test
    fun `summary renders fields and drops absent ones`() {
        val fields = NetworkTelemetry("1.2.3.4", 443, null, 10_001, "com.example", 5L,
            TelemetrySource.LIVE_SCAN, 6L).toFieldMap()
        val s = display.summary("network_monitor", fields)!!
        assertTrue(s, s.contains("com.example") && s.contains("1.2.3.4:443"))
        assertTrue(s, !s.contains("null") && !s.contains("  ") && s == s.trim())
        assertNull(display.summary("app_scanner", mapOf("package_name" to "x")))
    }

    @Test
    fun `parse rejects a template that is not a string`() {
        assertTrue(runCatching { EventDisplay.parse("dns_monitor: [1, 2]") }.isFailure)
    }
}
