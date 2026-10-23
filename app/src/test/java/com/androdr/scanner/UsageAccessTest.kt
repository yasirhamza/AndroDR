package com.androdr.scanner

import android.Manifest
import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Review m8 (C1 fix round 1): Usage Access is granted by AppOps `MODE_ALLOWED`, or by
 * `MODE_DEFAULT` when the permission itself is held (adb `pm grant`, MDM). Since C1 the live scan's
 * usage collection depends on this check, so `MODE_DEFAULT` must not read as no access.
 */
class UsageAccessTest {
    private fun context(mode: Int, permission: Int): Context {
        val appOps = mockk<AppOpsManager> {
            every { unsafeCheckOpNoThrow(any(), any(), any()) } returns mode
            @Suppress("DEPRECATION")
            every { checkOpNoThrow(any<String>(), any(), any()) } returns mode
        }
        return mockk(relaxed = true) {
            every { getSystemService(Context.APP_OPS_SERVICE) } returns appOps
            every { packageName } returns "com.androdr"
            every { checkCallingOrSelfPermission(Manifest.permission.PACKAGE_USAGE_STATS) } returns permission
        }
    }

    @Test
    fun `MODE_ALLOWED is access`() {
        assertTrue(UsageAccess.isGranted(context(AppOpsManager.MODE_ALLOWED, PackageManager.PERMISSION_DENIED)))
    }

    @Test
    fun `MODE_DEFAULT defers to the permission`() {
        assertTrue(UsageAccess.isGranted(context(AppOpsManager.MODE_DEFAULT, PackageManager.PERMISSION_GRANTED)))
        assertFalse(UsageAccess.isGranted(context(AppOpsManager.MODE_DEFAULT, PackageManager.PERMISSION_DENIED)))
    }

    @Test
    fun `MODE_IGNORED is no access even with the permission`() {
        assertFalse(UsageAccess.isGranted(context(AppOpsManager.MODE_IGNORED, PackageManager.PERMISSION_GRANTED)))
    }
}
