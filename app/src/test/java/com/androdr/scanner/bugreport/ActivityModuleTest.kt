package com.androdr.scanner.bugreport

import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.OemPrefixResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ActivityModuleTest {

    private val mockIndicatorResolver: IndicatorResolver = mockk()
    private lateinit var module: ActivityModule

    @Before
    fun setUp() {
        every { mockIndicatorResolver.isKnownBadPackage(any()) } returns null
        val oemPrefixResolver: OemPrefixResolver = mockk()
        every { oemPrefixResolver.isOemPrefix(any(), any()) } answers {
            val pkg = firstArg<String>()
            pkg.startsWith("com.android.") ||
                pkg.startsWith("com.google.android.") ||
                pkg.startsWith("com.samsung.android.") ||
                pkg.startsWith("com.sec.android.") ||
                pkg.startsWith("com.qualcomm.") ||
                pkg.startsWith("com.mediatek.")
        }
        module = ActivityModule(oemPrefixResolver)
    }

    @Test
    fun `targetSections is package`() {
        assertEquals(listOf("package"), module.targetSections)
    }

    @Test
    fun `detects non-system http scheme handler`() = runBlocking {
        val section = """
            Activity Resolver Table:
              Schemes:
                  http:
                    12345 com.evil.browser/.MainActivity filter abcdef
                      Action: "android.intent.action.VIEW"
                      Category: "android.intent.category.BROWSABLE"
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.evil.browser" &&
                it["handled_scheme"] == "http" &&
                it["is_system_app"] == false
        })
    }

    @Test
    fun `detects content scheme handler`() = runBlocking {
        val section = """
            Activity Resolver Table:
              Schemes:
                  content:
                    12345 com.spy.fileviewer/.FileActivity filter abcdef
                      Action: "android.intent.action.VIEW"
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.spy.fileviewer" &&
                it["handled_scheme"] == "content"
        })
    }

    @Test
    fun `ignores system package handlers`() = runBlocking {
        val section = """
            Activity Resolver Table:
              Schemes:
                  http:
                    1000 com.android.browser/.BrowserActivity filter abcdef
                      Action: "android.intent.action.VIEW"
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.all { it["is_system_app"] == true })
    }

    @Test
    fun `empty section produces no telemetry`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.isEmpty())
    }

    @Test
    fun `missing schemes subsection produces no telemetry`() = runBlocking {
        val section = """
            Activity Resolver Table:
              Non-Data Actions:
                  android.intent.action.MAIN:
                    12345 com.example/.MainActivity filter abcdef
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, DeviceIdentity.UNKNOWN)
        assertTrue(result.telemetry.isEmpty())
    }
}
