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

    @Test
    fun `parses Android 16 u0aXXX UID format`() = runBlocking {
        val section = """
  Uid u0a398:
    state=bfgs
    capability=--------
    appWidgetVisible=false
    Package com.talabat:
      FINE_LOCATION (allow):
        null=[
          Access: [top-s] 2026-03-15 19:21:06.692
      CAMERA (allow):
        null=[
          Access: [top-s] 2026-03-20 10:15:00.000
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        // u0a398 = user 0, app 398 = UID 10398 (not system)
        assertTrue("Should have telemetry for user app", result.telemetry.isNotEmpty())
        assertTrue("Should have timeline for non-system app", result.timeline.isNotEmpty())
        assertTrue(result.telemetry.all { it["is_system_app"] == false })
        assertTrue(result.telemetry.any { it["package_name"] == "com.talabat" })
    }

    @Test
    fun `parses u0s shared system UID format`() = runBlocking {
        val section = """
  Uid u0s1000:
    state=pers
    Package com.android.systemui:
      CAMERA (allow):
        null=[
          Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        // u0s1000 = user 0, shared system UID 1000 (is system)
        assertTrue("Should have telemetry", result.telemetry.isNotEmpty())
        assertTrue("System app should have no timeline", result.timeline.isEmpty())
        assertTrue(result.telemetry.all { it["is_system_app"] == true })
    }

    @Test
    fun `handles mixed numeric and u-format UIDs`() = runBlocking {
        val section = """
  Uid 1000:
    Package com.android.phone:
      READ_CALL_LOG (allow):
        Access: [fg-s] 2026-03-27 14:30:00
  Uid u0a150:
    Package com.whatsapp:
      CAMERA (allow):
        null=[
          Access: [top-s] 2026-03-20 21:33:43.634
      RECORD_AUDIO (allow):
        null=[
          Access: [top-s] 2026-03-20 21:34:00.000
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver)
        val systemEntries = result.telemetry.filter { it["is_system_app"] == true }
        val userEntries = result.telemetry.filter { it["is_system_app"] == false }
        assertTrue("Should have system entries", systemEntries.isNotEmpty())
        assertTrue("Should have user entries", userEntries.isNotEmpty())
        // Only user app should generate timeline
        assertTrue(result.timeline.all { it.description.contains("com.whatsapp") })
    }
}
