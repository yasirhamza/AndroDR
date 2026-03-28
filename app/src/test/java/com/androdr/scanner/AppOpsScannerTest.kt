package com.androdr.scanner

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
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
}
