package com.androdr.scanner.bugreport

import com.androdr.ioc.BadPackageInfo
import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class BatteryDailyModuleTest {

    private val mockIocResolver: IocResolver = mockk()
    private lateinit var module: BatteryDailyModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
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
                Update com.example.app vers=100
                Update com.example.app vers=0
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
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
              Update com.suspect.app vers=200
              Update com.suspect.app vers=100
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.timeline.any {
            it.category == "package_downgrade" &&
                it.description.contains("200") &&
                it.description.contains("100")
        })
    }

    @Test
    fun `flags IOC-matched uninstall as anti-forensics`() = runBlocking {
        every { mockIocResolver.isKnownBadPackage("com.mspy.android") } returns BadPackageInfo(
            packageName = "com.mspy.android",
            name = "mSpy",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Commercial stalkerware"
        )

        val section = """
            Package changes:
              Update com.mspy.android vers=0
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.timeline.any {
            it.severity == "HIGH" && it.description.contains("anti-forensics")
        })
    }

    @Test
    fun `empty section produces no events`() = runBlocking {
        val result = module.analyze("", mockIocResolver)
        assertTrue(result.timeline.isEmpty())
        assertTrue(result.telemetry.isEmpty())
    }

    @Test
    fun `deduplicates repeated entries`() = runBlocking {
        val section = """
            Package changes:
              Update com.example.app vers=100
              Update com.example.app vers=100
              Update com.example.app vers=100
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        val updateEvents = result.timeline.filter {
            it.category == "package_update" && it.description.contains("com.example.app")
        }
        assertEquals(1, updateEvents.size)
    }
}
