package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.OemPrefixResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AccessibilityModuleTest {

    private val mockIndicatorResolver: IndicatorResolver = mockk()
    private lateinit var module: AccessibilityModule

    @Before
    fun setUp() {
        every { mockIndicatorResolver.isKnownBadPackage(any()) } returns null
        val oemPrefixResolver: OemPrefixResolver = mockk()
        every { oemPrefixResolver.isOemPrefix(any()) } answers {
            val pkg = firstArg<String>()
            pkg.startsWith("com.google.android.") ||
                pkg.startsWith("com.samsung.") ||
                pkg.startsWith("com.android.")
        }
        module = AccessibilityModule(oemPrefixResolver)
    }

    @Test
    fun `targetSections is accessibility`() {
        assertEquals(listOf("accessibility"), module.targetSections)
    }

    @Test
    fun `detects enabled accessibility service`() = runBlocking {
        val section = """
            User state[userData:0 currentUser:0]:
              isEnabled=1
              Enabled services:
                com.evil.spy/.SpyAccessibilityService
                com.google.android.marvin.talkback/.TalkBackService
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.evil.spy" &&
                it["is_system_app"] == false &&
                it["is_enabled"] == true
        })
    }

    @Test
    fun `ignores known system accessibility services`() = runBlocking {
        val section = """
            User state[userData:0 currentUser:0]:
              isEnabled=1
              Enabled services:
                com.google.android.marvin.talkback/.TalkBackService
                com.samsung.accessibility/.universalswitch.UniversalSwitchService
                com.android.talkback/.TalkBackService
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.all { it["is_system_app"] == true })
    }

    @Test
    fun `flags IOC-matched accessibility service in telemetry`() = runBlocking {
        val iocInfo = com.androdr.ioc.BadPackageInfo(
            packageName = "com.flexispy.android",
            name = "FlexiSPY",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Commercial stalkerware"
        )
        every { mockIndicatorResolver.isKnownBadPackage("com.flexispy.android") } returns iocInfo

        val section = """
            Enabled services:
                com.flexispy.android/.AccessibilityHelper
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.flexispy.android" &&
                it["is_system_app"] == false
        })
    }

    @Test
    fun `empty section produces no telemetry`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver)
        assertTrue(result.telemetry.isEmpty())
    }

    @Test
    fun `section without Enabled services line produces no telemetry`() = runBlocking {
        val section = """
            User state[userData:0 currentUser:0]:
              isEnabled=0
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.isEmpty())
    }
}
