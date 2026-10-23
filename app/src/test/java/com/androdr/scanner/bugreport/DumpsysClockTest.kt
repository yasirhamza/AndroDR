package com.androdr.scanner.bugreport

import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.time.Instant
import java.time.ZoneId
import java.util.TimeZone

/**
 * Ruling R27: every dumpsys wall-clock parser reads times with the import's one clock, from
 * `persist.sys.timezone`, with per-timestamp DST rules, never the analyzing device's zone.
 */
class DumpsysClockTest {
    private val jvmZone: TimeZone = TimeZone.getDefault()
    private val resolver = mockk<IndicatorResolver> { every { isKnownBadPackage(any()) } returns null }

    // A JVM zone unlike every capture zone below, so leaking it would show.
    @Before fun setUp() = TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Kiritimati"))

    @After fun tearDown() = TimeZone.setDefault(jvmZone)

    private fun props(zone: String) = "[ro.product.brand]: [google]\n[persist.sys.timezone]: [$zone]\n"

    private fun ms(iso: String) = Instant.parse(iso).toEpochMilli()

    @Test
    fun `the clock comes from persist sys timezone, else UTC flagged as assumed`() {
        val ny = DumpsysClock.fromSystemProperties(props("America/New_York"))
        assertEquals(ZoneId.of("America/New_York"), ny.zone)
        assertFalse(ny.assumedUtc)
        assertSame(DumpsysClock.ASSUMED_UTC, DumpsysClock.fromSystemProperties("[ro.product.brand]: [google]\n"))
        assertSame(DumpsysClock.ASSUMED_UTC, DumpsysClock.fromSystemProperties(null))
        assertSame("an unknown zone id is not guessed", DumpsysClock.ASSUMED_UTC,
            DumpsysClock.fromSystemProperties(props("Mars/Olympus")))
        assertTrue(DumpsysClock.ASSUMED_UTC.assumedUtc)
    }

    @Test
    fun `AppOps access times follow the capture zone across a DST transition`() = runBlocking {
        val clock = DumpsysClock.fromSystemProperties(props("America/New_York"))
        val section = """
            Uid 10150:
              Package com.example.chat:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-08 01:30:00
                RECORD_AUDIO (allow):
                  Access: [fg-s] 2026-03-08 03:30:00
        """.trimIndent()
        val times = AppOpsModule().analyze(section, resolver, DeviceIdentity.UNKNOWN, clock).telemetry
            .associate { it["operation"] to it["event_time_ms"] }
        assertEquals("EST before the change", ms("2026-03-08T06:30:00Z"), times["android:camera"])
        assertEquals("EDT after it: one real hour later", ms("2026-03-08T07:30:00Z"), times["android:record_audio"])
    }

    @Test
    fun `install times, the capture header and battery days use the same clock`() = runBlocking {
        val clock = DumpsysClock.fromSystemProperties(props("Asia/Qatar"))
        val pkg = """
            Package [com.example.chat] (ab12cd):
              firstInstallTime=2026-03-27 12:00:00
              lastUpdateTime=2026-03-27 12:00:00
        """.trimIndent()
        assertEquals(ms("2026-03-27T09:00:00Z"), InstallTimeModule().parseHistory(pkg, 0L, clock).single().timestamp)

        val header = "== dumpstate: 2026-03-28 10:15:30\n".byteInputStream()
        assertEquals(ms("2026-03-28T07:15:30Z"),
            DumpsysSectionParser().extractSectionsAndHeader(header, emptySet(), clock).captureTimeMs)

        val battery = """
            Daily stats:
              Current start time: 2026-03-28-01-00-01
              Package changes:
                -pkg=com.example.app vers=100
        """.trimIndent()
        val day = BatteryDailyModule().analyze(battery, resolver, DeviceIdentity.UNKNOWN, clock)
            .typed.batteryDailyEvents.single().timestamp
        assertEquals("the capture device's local midnight", ms("2026-03-27T21:00:00Z"), day)
    }

    @Test
    fun `the fallback reads wall-clock times as UTC whatever the analyzing zone`() = runBlocking {
        val section = """
            Uid 10150:
              Package com.example.chat:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 09:20:00
        """.trimIndent()
        val t = AppOpsModule().analyze(section, resolver, DeviceIdentity.UNKNOWN, DumpsysClock.ASSUMED_UTC)
            .telemetry.single()["event_time_ms"]
        assertEquals(ms("2026-03-27T09:20:00Z"), t)
    }
}
