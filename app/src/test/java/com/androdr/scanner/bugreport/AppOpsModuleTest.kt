package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AppOpsModuleTest {

    private val mockIndicatorResolver: IndicatorResolver = mockk()
    private lateinit var module: AppOpsModule

    @Before
    fun setUp() {
        every { mockIndicatorResolver.isKnownBadPackage(any()) } returns null
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

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.suspicious.installer" &&
                it["operation"] == "android:request_install_packages" &&
                it["is_system_app"] == false
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

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.android.shell" &&
                it["operation"] == "android:camera"
        })
    }

    @Test
    fun `flags IOC-matched package in telemetry`() = runBlocking {
        val iocInfo = com.androdr.ioc.BadPackageInfo(
            packageName = "com.flexispy.android",
            name = "FlexiSPY",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Commercial stalkerware"
        )
        every { mockIndicatorResolver.isKnownBadPackage("com.flexispy.android") } returns iocInfo

        val section = """
            Uid 10200:
              Package com.flexispy.android:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.telemetry.any {
            it["package_name"] == "com.flexispy.android" &&
                it["operation"] == "android:camera" &&
                it["is_system_app"] == false
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

        val result = module.analyze(section, mockIndicatorResolver)
        assertTrue(result.timeline.any { it.category == "permission_use" })
    }

    @Test
    fun `normal system app ops produce telemetry with is_system_app true`() = runBlocking {
        val section = """
            Uid 1000:
              Package com.android.systemui:
                WAKE_LOCK (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        // WAKE_LOCK is not a dangerous op so telemetry should be empty
        assertTrue(result.telemetry.isEmpty())
    }

    @Test
    fun `empty section produces no telemetry or timeline`() = runBlocking {
        val result = module.analyze("", mockIndicatorResolver)
        assertTrue(result.telemetry.isEmpty())
        assertTrue(result.timeline.isEmpty())
    }
}
