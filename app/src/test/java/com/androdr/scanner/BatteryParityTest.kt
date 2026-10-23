package com.androdr.scanner

import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import com.androdr.scanner.bugreport.BatteryDailyModule
import com.androdr.sigma.toFieldMap
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDate
import java.time.ZoneOffset

/** Every row the battery module puts on the interim timeline also exists as a typed record. */
class BatteryParityTest {

    private val resolver: IndicatorResolver = mockk<IndicatorResolver>().also {
        every { it.isKnownBadPackage(any()) } returns null
    }

    private val section = """
        Daily stats:
          Current start time: 2026-03-27-01-00-01
          Package changes:
            +pkg=com.example.alpha vers=200
            +pkg=com.example.alpha vers=100
            -pkg=com.example.beta vers=7
    """.trimIndent()

    private fun run(text: String, module: BatteryDailyModule = BatteryDailyModule()) =
        runBlocking { module.analyze(text, resolver, DeviceIdentity.UNKNOWN) }

    @Test
    fun `every old battery row has a typed record`() {
        val result = run(section)
        val typed = result.typed.batteryDailyEvents
        assertTrue(result.timeline.isNotEmpty())
        for (row in result.timeline) {
            assertTrue(
                "no typed record for ${row.category}: ${row.description}",
                typed.any { it.eventType == row.category && row.description.contains(it.packageName!!) },
            )
        }
        // one record per parsed entry, plus the downgrade
        assertEquals(
            setOf("package_update", "package_uninstall", "package_downgrade"),
            typed.map { it.eventType }.toSet(),
        )
        assertEquals(4, typed.size)
    }

    @Test
    fun `day timestamp matches the section header at day precision`() {
        val expected = LocalDate.of(2026, 3, 27).atStartOfDay().toInstant(ZoneOffset.UTC).toEpochMilli()
        for (event in run(section).typed.batteryDailyEvents) {
            assertEquals(expected, event.timestamp)
            assertEquals("day", event.timestampPrecision)
            val map = event.toFieldMap()
            assertEquals(expected, map["timestamp"])
            assertEquals("day", map["timestamp_precision"])
            assertTrue(map["version"] is Long)
        }
    }

    @Test
    fun `no date in the section means no timestamp fields`() {
        val event = run("Package changes:\n  +pkg=com.x vers=1\n").typed.batteryDailyEvents.single()
        assertNull(event.timestamp)
        assertFalse(event.toFieldMap().containsKey("timestamp"))
        assertFalse(event.toFieldMap().containsKey("timestamp_precision"))
    }

    @Test
    fun `module stops at the record bound and reports the trip`() {
        val lines = (1..10).joinToString("\n") { "    +pkg=com.p$it vers=$it" }
        val result = run("Package changes:\n$lines\n", BatteryDailyModule(maxRecords = 3))
        assertEquals(3, result.typed.batteryDailyEvents.size)
        assertEquals(3, result.truncatedAt)
    }
}
