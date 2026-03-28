package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AccessibilityModuleTest {

    private val mockIocResolver: IocResolver = mockk()
    private lateinit var module: AccessibilityModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        module = AccessibilityModule()
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

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.category == "AccessibilityAbuse" &&
                it.description.contains("com.evil.spy")
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

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `flags IOC-matched accessibility service as CRITICAL`() = runBlocking {
        val iocInfo = com.androdr.ioc.BadPackageInfo(
            packageName = "com.flexispy.android",
            name = "FlexiSPY",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Commercial stalkerware"
        )
        every { mockIocResolver.isKnownBadPackage("com.flexispy.android") } returns iocInfo

        val section = """
            Enabled services:
                com.flexispy.android/.AccessibilityHelper
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.severity == "CRITICAL" && it.description.contains("FlexiSPY")
        })
    }

    @Test
    fun `empty section produces no findings`() = runBlocking {
        val result = module.analyze("", mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `section without Enabled services line produces no findings`() = runBlocking {
        val section = """
            User state[userData:0 currentUser:0]:
              isEnabled=0
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }
}
