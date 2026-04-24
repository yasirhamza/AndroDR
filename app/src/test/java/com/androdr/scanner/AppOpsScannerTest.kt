package com.androdr.scanner

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AppOpsScannerTest {

    private val mockContext: Context = mockk(relaxed = true)

    @Test
    fun `returns empty when AppOpsManager unavailable`() = runTest {
        every { mockContext.getSystemService(Context.APP_OPS_SERVICE) } returns null
        assertTrue(AppOpsScanner(mockContext).collectTelemetry().isEmpty())
    }

    @Test
    fun `returns empty when no packages installed`() = runTest {
        val mockOps: AppOpsManager = mockk(relaxed = true)
        val mockPm: PackageManager = mockk(relaxed = true)
        every { mockContext.getSystemService(Context.APP_OPS_SERVICE) } returns mockOps
        every { mockContext.packageManager } returns mockPm
        every { mockPm.getInstalledPackages(any<Int>()) } returns emptyList()
        assertTrue(AppOpsScanner(mockContext).collectTelemetry().isEmpty())
    }

    @Test
    fun `skips package that did not request camera even when MODE_ALLOWED is returned`() = runTest {
        // Regression: unsafeCheckOpNoThrow returns MODE_ALLOWED as the default for
        // OPSTR_CAMERA on most Android builds, even for packages that never declared
        // android.permission.CAMERA in their manifest. That produced FP where AndroDR
        // flagged itself for camera access despite having no camera permission. See #147.
        val mockOps: AppOpsManager = mockk(relaxed = true)
        val mockPm: PackageManager = mockk(relaxed = true)
        every { mockContext.getSystemService(Context.APP_OPS_SERVICE) } returns mockOps
        every { mockContext.packageManager } returns mockPm
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(
            fakePackage("com.androdr", requestedPermissions = emptyArray())
        )
        every { mockOps.unsafeCheckOpNoThrow(any(), any(), any()) } returns AppOpsManager.MODE_ALLOWED

        val results = AppOpsScanner(mockContext).collectTelemetry()

        assertTrue(
            "Expected no telemetry for package without camera/mic declared permissions; got $results",
            results.none {
                it.operation == AppOpsManager.OPSTR_CAMERA ||
                    it.operation == AppOpsManager.OPSTR_RECORD_AUDIO
            }
        )
    }

    @Test
    fun `records camera op when package declared CAMERA permission and MODE_ALLOWED`() = runTest {
        val mockOps: AppOpsManager = mockk(relaxed = true)
        val mockPm: PackageManager = mockk(relaxed = true)
        every { mockContext.getSystemService(Context.APP_OPS_SERVICE) } returns mockOps
        every { mockContext.packageManager } returns mockPm
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(
            fakePackage("com.example.camera", requestedPermissions = arrayOf("android.permission.CAMERA"))
        )
        every { mockOps.unsafeCheckOpNoThrow(any(), any(), any()) } returns AppOpsManager.MODE_ALLOWED

        val results = AppOpsScanner(mockContext).collectTelemetry()

        assertEquals(
            1, results.count { it.operation == AppOpsManager.OPSTR_CAMERA && it.packageName == "com.example.camera" }
        )
    }

    private fun fakePackage(
        packageName: String,
        requestedPermissions: Array<String>,
        isSystem: Boolean = false,
    ): PackageInfo {
        val appInfo = ApplicationInfo().apply {
            this.packageName = packageName
            this.uid = 10_000
            this.flags = if (isSystem) ApplicationInfo.FLAG_SYSTEM else 0
        }
        return PackageInfo().apply {
            this.packageName = packageName
            this.applicationInfo = appInfo
            this.requestedPermissions = requestedPermissions
        }
    }
}
