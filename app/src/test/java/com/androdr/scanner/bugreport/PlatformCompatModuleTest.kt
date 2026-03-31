package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PlatformCompatModuleTest {

    private val mockIocResolver: IocResolver = mockk()
    private lateinit var module: PlatformCompatModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        module = PlatformCompatModule()
    }

    @Test
    fun `targetSections is platform_compat`() {
        assertEquals(listOf("platform_compat"), module.targetSections)
    }

    @Test
    fun `detects DOWNSCALED compat override`() = runBlocking {
        val section = """
            Compat overrides:
              168419799, {packageName=com.suspicious.app, enabled=true}
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.suspicious.app" &&
                it["is_downscaled"] == true
        })
    }

    @Test
    fun `ignores non-DOWNSCALED overrides`() = runBlocking {
        val section = """
            Compat overrides:
              999999999, {packageName=com.normal.app, enabled=true}
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.telemetry.isEmpty())
    }

    @Test
    fun `empty section produces no telemetry`() = runBlocking {
        val result = module.analyze("", mockIocResolver)
        assertTrue(result.telemetry.isEmpty())
    }
}
