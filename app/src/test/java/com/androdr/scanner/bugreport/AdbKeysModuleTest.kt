package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AdbKeysModuleTest {

    private val mockIndicatorResolver: IndicatorResolver = mockk()
    private lateinit var module: AdbKeysModule

    @Before
    fun setUp() {
        every { mockIndicatorResolver.isKnownBadPackage(any()) } returns null
        module = AdbKeysModule()
    }

    @Test
    fun `targetSections is adb only`() {
        assertEquals(listOf("adb"), module.targetSections)
    }

    @Test
    fun `detects ADB trusted key with host`() = runBlocking {
        val section = """
            USB debugging: enabled
            Trusted keys:
              QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFh user@workstation
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.any {
            it["source"] == "adb_trusted_key" &&
                it["host"] == "user@workstation"
        })
        assertTrue(result.timeline.any {
            it.category == "adb_trusted_key" &&
                it.description.contains("user@workstation")
        })
    }

    @Test
    fun `detects key without host`() = runBlocking {
        val section = """
            USB debugging: enabled
            Trusted keys:
              QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFh
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.any {
            it["source"] == "adb_trusted_key" &&
                it["host"] == "unknown"
        })
    }

    @Test
    fun `empty section produces no telemetry`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver)
        assertTrue(result.telemetry.isEmpty())
        assertTrue(result.timeline.isEmpty())
    }
}
