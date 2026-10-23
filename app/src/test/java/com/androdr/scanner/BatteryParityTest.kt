package com.androdr.scanner

import com.androdr.ioc.BadPackageInfo
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

/**
 * Pins the battery module's interim timeline rows to what the pre-typed-records module
 * (commit cdeefc4) produced for the same input, and pins the typed records exactly.
 */
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

    private val day = LocalDate.of(2026, 3, 27).atStartOfDay().toInstant(ZoneOffset.UTC).toEpochMilli()

    private fun run(
        text: String,
        module: BatteryDailyModule = BatteryDailyModule(),
        r: IndicatorResolver = resolver,
    ) = runBlocking { module.analyze(text, r, DeviceIdentity.UNKNOWN) }

    // Rows captured from the cdeefc4 module for `section` (source battery_daily, severity INFO).
    private val oldRows = listOf(
        "package_update" to "App updated: com.example.alpha (version 200)",
        "package_update" to "App updated: com.example.alpha (version 100)",
        "package_uninstall" to "App uninstalled: com.example.beta",
        "package_downgrade" to
            "Version downgrade: com.example.alpha (200 → 100) — possible exploit re-application",
    )

    @Test
    fun `timeline rows equal the rows the pre-typed module produced`() {
        val rows = run(section).timeline
        assertEquals(oldRows, rows.map { it.category to it.description })
        assertTrue(rows.all { it.source == "battery_daily" && it.severity == "INFO" && it.timestamp == -1L })
    }

    @Test
    fun `IOC-matched uninstall keeps its extra anti-forensics row`() {
        val ioc: IndicatorResolver = mockk()
        every { ioc.isKnownBadPackage(any()) } returns null
        every { ioc.isKnownBadPackage("com.example.beta") } returns BadPackageInfo(
            packageName = "com.example.beta", name = "BetaSpy", category = "STALKERWARE",
            severity = "CRITICAL", description = "d",
        )
        val rows = run(section, r = ioc).timeline.map { it.category to it.description }
        // cdeefc4 put the IOC row directly after the plain uninstall row, before the downgrade.
        assertEquals(
            listOf(
                oldRows[0], oldRows[1], oldRows[2],
                "package_uninstall" to "Known STALKERWARE package 'com.example.beta' (BetaSpy) " +
                    "was uninstalled — possible anti-forensics",
                oldRows[3],
            ),
            rows,
        )
        // The IOC row is not a separate parsed entry: typed records are unchanged.
        assertEquals(4, run(section, r = ioc).typed.batteryDailyEvents.size)
    }

    @Test
    fun `typed records are exactly the expected tuples`() {
        val typed = run(section).typed.batteryDailyEvents
        assertEquals(
            listOf(
                listOf("package_update", "com.example.alpha", 200L, day),
                listOf("package_update", "com.example.alpha", 100L, day),
                listOf("package_uninstall", "com.example.beta", 7L, day),
                listOf("package_downgrade", "com.example.alpha", 100L, day),
            ),
            typed.map { listOf(it.eventType, it.packageName, it.version, it.timestamp) },
        )
        for (event in typed) {
            assertEquals("day", event.timestampPrecision)
            assertEquals(0, event.dayIndex)
            val map = event.toFieldMap()
            assertEquals(day, map["timestamp"])
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
