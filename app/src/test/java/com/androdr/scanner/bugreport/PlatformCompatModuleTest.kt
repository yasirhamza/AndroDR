package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import com.androdr.sigma.toFieldMap
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
        assertTrue(result.typed.platformCompatChanges.any {
            it.packageName == "com.suspicious.app" && it.changeId == "168419799" && it.enabled == true
        })
    }

    @Test
    fun `emits telemetry for arbitrary ChangeIds`() = runBlocking {
        val section = """
            Compat overrides:
              999999999, {packageName=com.normal.app, enabled=true}
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.typed.platformCompatChanges.any { it.changeId == "999999999" })
    }

    @Test
    fun `empty section produces no telemetry`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.isEmpty())
        assertTrue(result.typed.platformCompatChanges.isEmpty())
    }

    @Test
    fun `enabled is true false or absent as the line states`() = runBlocking {
        val section = """
            Compat overrides:
              1, {packageName=com.a, enabled=true}
              2, {packageName=com.b, enabled=false}
              3, {packageName=com.c}
        """.trimIndent()
        val changes = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
            .typed.platformCompatChanges.associateBy { it.changeId }
        assertEquals(true, changes.getValue("1").enabled)
        assertEquals(false, changes.getValue("2").enabled)
        assertEquals(null, changes.getValue("3").enabled)
        assertEquals(true, changes.getValue("1").toFieldMap()["enabled"])
        assertEquals(false, changes.getValue("2").toFieldMap()["enabled"])
        assertTrue(!changes.getValue("3").toFieldMap().containsKey("enabled"))
    }

    @Test
    fun `module stops at the record bound and reports the trip`() = runBlocking {
        val section = "Compat overrides:\n" + (1..10).joinToString("\n") { "  $it, {packageName=com.p$it}" }
        val result = PlatformCompatModule(maxRecords = 3)
            .analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertEquals(3, result.typed.platformCompatChanges.size)
        assertEquals(3, result.truncatedAt)
    }
}
