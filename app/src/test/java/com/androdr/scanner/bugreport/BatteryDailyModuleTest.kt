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
        assertTrue(result.timeline.any {
            it.category == "package_update" && it.description.contains("com.example.app")
        })
        assertTrue(result.timeline.any {
            it.category == "package_uninstall" && it.description.contains("com.example.app")
        })
    }

    @Test
    fun `detects version downgrade`() = runBlocking {
        val section = """
            Package changes:
              +pkg=com.suspect.app vers=200
              +pkg=com.suspect.app vers=100
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.timeline.any {
            it.category == "package_downgrade" &&
                it.description.contains("200") &&
                it.description.contains("100")
        })
    }

    @Test
    fun `flags IOC-matched uninstall as anti-forensics`() = runBlocking {
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
        // Severity no longer hardcoded; rule engine assigns it via SIGMA YAML (plan 6).
        assertTrue(result.timeline.any {
            it.description.contains("anti-forensics")
        })
    }

    @Test
    fun `empty section produces no events`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.timeline.isEmpty())
        assertTrue(result.telemetry.isEmpty())
    }

    @Test
    fun `deduplicates repeated entries`() = runBlocking {
        val section = """
            Package changes:
              +pkg=com.example.app vers=100
              +pkg=com.example.app vers=100
              +pkg=com.example.app vers=100
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        val updateEvents = result.timeline.filter {
            it.category == "package_update" && it.description.contains("com.example.app")
        }
        assertEquals(1, updateEvents.size)
    }
}
