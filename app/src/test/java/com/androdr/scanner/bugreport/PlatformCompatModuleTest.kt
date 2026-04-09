package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PlatformCompatModuleTest {

    private val mockIndicatorResolver: IndicatorResolver = mockk()
    private lateinit var module: PlatformCompatModule

    @Before
    fun setUp() {
        every { mockIndicatorResolver.isKnownBadPackage(any()) } returns null
        module = PlatformCompatModule()
    }

    @Test
    fun `targetSections is platform_compat`() {
        assertEquals(listOf("platform_compat"), module.targetSections)
    }

    @Test
    fun `emits compat override telemetry regardless of ChangeId`() = runBlocking {
        // Hardcoded CHANGE_ID_DOWNSCALED filter removed. SIGMA rules in plan 6
        // match the ChangeId themselves and decide severity.
        val section = """
            Compat overrides:
              168419799, {packageName=com.suspicious.app, enabled=true}
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.suspicious.app" && it["change_id"] == "168419799"
        })
    }

    @Test
    fun `emits telemetry for arbitrary ChangeIds`() = runBlocking {
        val section = """
            Compat overrides:
              999999999, {packageName=com.normal.app, enabled=true}
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.any { it["change_id"] == "999999999" })
    }

    @Test
    fun `empty section produces no telemetry`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.isEmpty())
    }
}
