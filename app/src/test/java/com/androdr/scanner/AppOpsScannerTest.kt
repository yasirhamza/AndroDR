package com.androdr.scanner

import android.app.AppOpsManager
import android.content.Context
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
    fun `returns empty when no packages have ops`() = runTest {
        val mockOps: AppOpsManager = mockk(relaxed = true)
        every { mockContext.getSystemService(Context.APP_OPS_SERVICE) } returns mockOps
        every { mockOps.getPackagesForOps(any()) } returns null
        assertTrue(AppOpsScanner(mockContext).collectTelemetry().isEmpty())
    }
}
