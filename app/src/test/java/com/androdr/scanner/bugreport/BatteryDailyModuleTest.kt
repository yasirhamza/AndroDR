package com.androdr.scanner.bugreport

import com.androdr.ioc.BadPackageInfo
import com.androdr.ioc.IndicatorResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class BatteryDailyModuleTest {

    private val mockIndicatorResolver: IndicatorResolver = mockk()
    private lateinit var module: BatteryDailyModule

    @Before
    fun setUp() {
        every { mockIndicatorResolver.isKnownBadPackage(any()) } returns null
        module = BatteryDailyModule()
    }

    @Test
    fun `targetSections is batterystats`() {
        assertEquals(listOf("batterystats"), module.targetSections)
    }

    @Test
    fun `detects package install and uninstall`() = runBlocking {
        val section = """
            Daily stats:
              Current start time: 2026-03-28-01-00-01
              Package changes:
                +pkg=com.example.app vers=100
                -pkg=com.example.app vers=100
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        val events = result.typed.batteryDailyEvents
        assertTrue(events.any { it.eventType == "package_update" && it.packageName == "com.example.app" })
        assertTrue(events.any { it.eventType == "package_uninstall" && it.packageName == "com.example.app" })
    }

    @Test
    fun `detects version downgrade`() = runBlocking {
        val section = """
            Package changes:
              +pkg=com.suspect.app vers=200
              +pkg=com.suspect.app vers=100
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.typed.batteryDailyEvents.any {
            it.eventType == "package_downgrade" &&
                it.description.contains("200") &&
                it.description.contains("100")
        })
    }

    /**
     * C3: the module no longer hand-builds an "anti-forensics" row from an IOC lookup (detection is
     * rule-driven). The uninstall is a typed record carrying its package, which a battery_daily
     * rule can look up; the module never consults the IOC resolver.
     */
    @Test
    fun `an IOC-listed uninstall is a plain typed record and the module looks nothing up`() = runBlocking {
        every { mockIndicatorResolver.isKnownBadPackage("com.mspy.android") } returns BadPackageInfo(
            packageName = "com.mspy.android",
            name = "mSpy",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Commercial stalkerware"
        )

        val section = """
            Package changes:
              -pkg=com.mspy.android vers=100
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        val event = result.typed.batteryDailyEvents.single()
        assertEquals("package_uninstall", event.eventType)
        assertEquals("com.mspy.android", event.packageName)
        io.mockk.verify(exactly = 0) { mockIndicatorResolver.isKnownBadPackage(any()) }
    }

    @Test
    fun `empty section produces no events`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.isEmpty())
        assertTrue(result.typed.batteryDailyEvents.isEmpty())
    }

    /** Every parsed entry is a record (emitters emit all facts; the old row dedup is gone with the rows). */
    @Test
    fun `repeated entries are each a record`() = runBlocking {
        val section = """
            Package changes:
              +pkg=com.example.app vers=100
              +pkg=com.example.app vers=100
              +pkg=com.example.app vers=100
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        val updateEvents = result.typed.batteryDailyEvents.filter {
            it.eventType == "package_update" && it.packageName == "com.example.app"
        }
        assertEquals(3, updateEvents.size)
    }
}
