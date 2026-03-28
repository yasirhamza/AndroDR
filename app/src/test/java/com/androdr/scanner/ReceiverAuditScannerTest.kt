package com.androdr.scanner

import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertTrue
import org.junit.Test

class ReceiverAuditScannerTest {

    private val mockContext: Context = mockk(relaxed = true)
    private val mockPackageManager: PackageManager = mockk(relaxed = true)

    private fun createScanner(): ReceiverAuditScanner {
        every { mockContext.packageManager } returns mockPackageManager
        return ReceiverAuditScanner(mockContext)
    }

    private fun mockResolveInfo(packageName: String, name: String, isSystem: Boolean): ResolveInfo {
        val ri = ResolveInfo()
        ri.activityInfo = ActivityInfo()
        ri.activityInfo.packageName = packageName
        ri.activityInfo.name = name
        ri.activityInfo.applicationInfo = ApplicationInfo().apply {
            this.packageName = packageName
            flags = if (isSystem) ApplicationInfo.FLAG_SYSTEM else 0
        }
        return ri
    }

    @Test
    fun `returns telemetry for sensitive intent receivers`() = runTest {
        val intentSlot = slot<Intent>()
        every { mockPackageManager.queryBroadcastReceivers(capture(intentSlot), any<Int>()) } answers {
            if (intentSlot.captured.action == "android.provider.Telephony.SMS_RECEIVED") {
                listOf(mockResolveInfo("com.evil.sms", ".SmsReceiver", false))
            } else emptyList()
        }
        val telemetry = createScanner().collectTelemetry()
        assertTrue(telemetry.any {
            it.packageName == "com.evil.sms" && it.intentAction == "android.provider.Telephony.SMS_RECEIVED"
        })
    }

    @Test
    fun `returns empty when no receivers`() = runTest {
        every { mockPackageManager.queryBroadcastReceivers(any(), any<Int>()) } returns emptyList()
        assertTrue(createScanner().collectTelemetry().isEmpty())
    }
}
