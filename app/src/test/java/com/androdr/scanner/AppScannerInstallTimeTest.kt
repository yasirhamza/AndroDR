package com.androdr.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.androdr.ioc.KnownAppResolver
import com.androdr.ioc.OemPrefixResolver
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class AppScannerInstallTimeTest {

    @Test
    fun `buildTelemetryForPackage populates firstInstallTime and lastUpdateTime`() {
        val context = mockk<Context>(relaxed = true)
        val knownAppResolver = mockk<KnownAppResolver>(relaxed = true)
        val oemPrefixResolver = mockk<OemPrefixResolver>(relaxed = true)
        every { knownAppResolver.lookup(any()) } returns null
        every { oemPrefixResolver.isTrustedInstaller(any()) } returns false
        every { oemPrefixResolver.isOemPrefix(any()) } returns false
        every { oemPrefixResolver.isPartnershipPrefix(any()) } returns false

        val appInfo = ApplicationInfo().apply {
            packageName = "com.example.test"
            flags = ApplicationInfo.FLAG_SYSTEM // avoid APK hashing / cert path
            sourceDir = "/nonexistent/base.apk"
        }
        val pkg = PackageInfo().apply {
            packageName = "com.example.test"
            firstInstallTime = 1_700_000_000_000L
            lastUpdateTime = 1_710_000_000_000L
            applicationInfo = appInfo
        }

        val pm = mockk<PackageManager>(relaxed = true)
        every { pm.getApplicationLabel(any()) } returns "TestApp"
        every { pm.getLaunchIntentForPackage(any()) } returns null

        val scanner = AppScanner(context, knownAppResolver, oemPrefixResolver)
        val telemetry = scanner.buildTelemetryForPackage(pm, pkg)

        assertNotNull(telemetry)
        assertEquals(1_700_000_000_000L, telemetry!!.firstInstallTime)
        assertEquals(1_710_000_000_000L, telemetry.lastUpdateTime)
    }
}
