package com.androdr.scanner

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.ResolveInfo
import android.content.pm.ServiceInfo
import android.view.accessibility.AccessibilityManager
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AccessibilityAuditScannerTest {

    private val mockContext: Context = mockk(relaxed = true)
    private val mockAccessibilityManager: AccessibilityManager = mockk()

    private fun createScanner(): AccessibilityAuditScanner {
        every { mockContext.getSystemService(Context.ACCESSIBILITY_SERVICE) } returns mockAccessibilityManager
        return AccessibilityAuditScanner(mockContext)
    }

    private fun mockServiceInfo(packageName: String, serviceName: String, isSystem: Boolean = false): AccessibilityServiceInfo {
        val info = mockk<AccessibilityServiceInfo>()
        val resolveInfo = mockk<ResolveInfo>()
        val serviceInfo = ServiceInfo()
        serviceInfo.packageName = packageName
        serviceInfo.name = serviceName
        serviceInfo.applicationInfo = ApplicationInfo().apply {
            this.packageName = packageName
            flags = if (isSystem) ApplicationInfo.FLAG_SYSTEM else 0
        }
        resolveInfo.serviceInfo = serviceInfo
        every { info.resolveInfo } returns resolveInfo
        return info
    }

    @Test
    fun `returns telemetry for enabled services`() = runTest {
        every {
            mockAccessibilityManager.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            )
        } returns listOf(
            mockServiceInfo("com.evil.spy", ".SpyService"),
            mockServiceInfo("com.google.android.marvin.talkback", ".TalkBackService", true)
        )
        val scanner = createScanner()
        val telemetry = scanner.collectTelemetry()
        assertEquals(2, telemetry.size)
        assertTrue(telemetry.any { it.packageName == "com.evil.spy" && !it.isSystemApp })
        assertTrue(telemetry.any { it.packageName == "com.google.android.marvin.talkback" && it.isSystemApp })
    }

    @Test
    fun `returns empty when no services`() = runTest {
        every {
            mockAccessibilityManager.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            )
        } returns emptyList()
        val telemetry = createScanner().collectTelemetry()
        assertTrue(telemetry.isEmpty())
    }

    @Test
    fun `returns empty when manager unavailable`() = runTest {
        every { mockContext.getSystemService(Context.ACCESSIBILITY_SERVICE) } returns null
        val telemetry = AccessibilityAuditScanner(mockContext).collectTelemetry()
        assertTrue(telemetry.isEmpty())
    }
}
