package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AppOpsModuleTest {

    private val mockIocResolver: IocResolver = mockk()
    private lateinit var module: AppOpsModule

    @Before
    fun setUp() {
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        module = AppOpsModule()
    }

    @Test
    fun `targetSections is appops`() {
        assertEquals(listOf("appops"), module.targetSections)
    }

    @Test
    fun `detects REQUEST_INSTALL_PACKAGES usage`() = runBlocking {
        val section = """
            Uid 10150:
              Package com.suspicious.installer:
                REQUEST_INSTALL_PACKAGES (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.category == "AppOpsAbuse" &&
                it.description.contains("REQUEST_INSTALL_PACKAGES") &&
                it.description.contains("com.suspicious.installer")
        })
    }

    @Test
    fun `detects shell package permission usage`() = runBlocking {
        val section = """
            Uid 2000:
              Package com.android.shell:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.category == "AppOpsAbuse" &&
                it.description.contains("com.android.shell")
        })
    }

    @Test
    fun `flags IOC-matched package as CRITICAL`() = runBlocking {
        val iocInfo = com.androdr.ioc.BadPackageInfo(
            packageName = "com.flexispy.android",
            name = "FlexiSPY",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Commercial stalkerware"
        )
        every { mockIocResolver.isKnownBadPackage("com.flexispy.android") } returns iocInfo

        val section = """
            Uid 10200:
              Package com.flexispy.android:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.any {
            it.severity == "CRITICAL" && it.description.contains("FlexiSPY")
        })
    }

    @Test
    fun `generates timeline events for permission access`() = runBlocking {
        val section = """
            Uid 10150:
              Package com.some.app:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
                RECORD_AUDIO (allow):
                  Access: [fg-s] 2026-03-27 14:35:00
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.timeline.any { it.category == "permission_use" })
    }

    @Test
    fun `normal system app ops do not trigger findings`() = runBlocking {
        val section = """
            Uid 1000:
              Package com.android.systemui:
                WAKE_LOCK (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIocResolver)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `empty section produces no findings`() = runBlocking {
        val result = module.analyze("", mockIocResolver)
        assertTrue(result.findings.isEmpty())
        assertTrue(result.timeline.isEmpty())
    }
}
