package com.androdr.scanner

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.content.pm.ActivityInfo
import android.content.res.Resources
import com.androdr.R
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import com.androdr.ioc.KnownAppResolver
import com.androdr.ioc.OemPrefixResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AppScannerTelemetryTest {

    private lateinit var context: Context
    private lateinit var pm: PackageManager
    private lateinit var knownAppResolver: KnownAppResolver
    private lateinit var oemPrefixResolver: OemPrefixResolver
    private lateinit var scanner: AppScanner

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        pm = mockk(relaxed = true)
        knownAppResolver = mockk(relaxed = true)

        val oemContext: Context = mockk(relaxed = true)
        val resources: Resources = mockk(relaxed = true)
        every { oemContext.resources } returns resources
        val yamlStream = javaClass.classLoader!!
            .getResourceAsStream("raw/known_oem_prefixes.yml")!!
        every { resources.openRawResource(R.raw.known_oem_prefixes) } returns yamlStream
        oemPrefixResolver = OemPrefixResolver(oemContext)

        every { context.packageManager } returns pm
        every { knownAppResolver.lookup(any()) } returns null

        scanner = AppScanner(context, knownAppResolver, oemPrefixResolver)
    }

    /**
     * Creates a [PackageInfo] with the given properties for use in tests.
     * By default the app is non-system with no special permissions or components.
     */
    private fun buildPackageInfo(
        pkgName: String,
        appLabel: String = pkgName,
        isSystem: Boolean = false,
        installerPkg: String? = null,
        permissions: Array<String>? = null,
        services: Array<ServiceInfo>? = null,
        receivers: Array<ActivityInfo>? = null
    ): PackageInfo {
        val appInfo = ApplicationInfo().apply {
            packageName = pkgName
            flags = if (isSystem) ApplicationInfo.FLAG_SYSTEM else 0
        }
        val pkgInfo = PackageInfo().apply {
            packageName = pkgName
            applicationInfo = appInfo
            requestedPermissions = permissions
            this.services = services
            this.receivers = receivers
        }

        every { pm.getApplicationLabel(appInfo) } returns appLabel

        // On JVM Build.VERSION.SDK_INT == 0, so the deprecated path is taken
        @Suppress("DEPRECATION")
        every { pm.getInstallerPackageName(pkgName) } returns installerPkg

        return pkgInfo
    }

    private fun installPackages(vararg packages: PackageInfo) {
        every { pm.getInstalledPackages(any<Int>()) } returns packages.toList()
    }

    // ── 1. Sideloaded app detection ─────────────────────────────────────────

    @Test
    fun `non-system app without trusted store or OEM prefix is sideloaded`() = runTest {
        val pkg = buildPackageInfo(
            pkgName = "com.shady.tracker",
            installerPkg = null
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        val telemetry = result[0]
        assertTrue("Expected isSideloaded = true", telemetry.isSideloaded)
        assertFalse("Expected isSystemApp = false", telemetry.isSystemApp)
        assertFalse("Expected fromTrustedStore = false", telemetry.fromTrustedStore)
    }

    // ── 2. Play Store app is not sideloaded ─────────────────────────────────

    @Test
    fun `app installed from Play Store is not sideloaded and from trusted store`() = runTest {
        val pkg = buildPackageInfo(
            pkgName = "com.example.legit",
            installerPkg = "com.android.vending"
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        val telemetry = result[0]
        assertFalse("Expected isSideloaded = false", telemetry.isSideloaded)
        assertTrue("Expected fromTrustedStore = true", telemetry.fromTrustedStore)
    }

    // ── 3. System app detection ─────────────────────────────────────────────

    @Test
    fun `app with FLAG_SYSTEM is detected as system app`() = runTest {
        val pkg = buildPackageInfo(
            pkgName = "com.android.settings",
            isSystem = true
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        assertTrue("Expected isSystemApp = true", result[0].isSystemApp)
    }

    // ── 4. Samsung OEM prefix treated as known OEM ──────────────────────────

    @Test
    fun `Samsung OEM package prefix is treated as known OEM app`() = runTest {
        val pkg = buildPackageInfo(
            pkgName = "com.samsung.android.tvplus",
            installerPkg = null
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        val telemetry = result[0]
        assertTrue("Expected isKnownOemApp = true", telemetry.isKnownOemApp)
        assertFalse("Expected isSideloaded = false for Samsung OEM app", telemetry.isSideloaded)
    }

    // ── 5. Surveillance permission counting ─────────────────────────────────

    @Test
    fun `surveillance permissions are counted correctly`() = runTest {
        val pkg = buildPackageInfo(
            pkgName = "com.example.spy",
            installerPkg = "com.android.vending",
            permissions = arrayOf(
                Manifest.permission.READ_CONTACTS,
                Manifest.permission.CAMERA
            )
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        val telemetry = result[0]
        assertEquals(2, telemetry.surveillancePermissionCount)
        assertTrue(telemetry.permissions.contains("READ_CONTACTS"))
        assertTrue(telemetry.permissions.contains("CAMERA"))
    }

    // ── 6. Accessibility service detection ──────────────────────────────────

    @Test
    fun `app with BIND_ACCESSIBILITY_SERVICE is detected`() = runTest {
        val svc = ServiceInfo().apply {
            permission = "android.permission.BIND_ACCESSIBILITY_SERVICE"
        }
        val pkg = buildPackageInfo(
            pkgName = "com.example.a11y",
            installerPkg = "com.android.vending",
            services = arrayOf(svc)
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        assertTrue("Expected hasAccessibilityService = true", result[0].hasAccessibilityService)
    }

    // ── 7. Device admin detection ───────────────────────────────────────────

    @Test
    fun `app with BIND_DEVICE_ADMIN receiver is detected`() = runTest {
        val recv = ActivityInfo().apply {
            permission = "android.permission.BIND_DEVICE_ADMIN"
        }
        val pkg = buildPackageInfo(
            pkgName = "com.example.admin",
            installerPkg = "com.android.vending",
            receivers = arrayOf(recv)
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        assertTrue("Expected hasDeviceAdmin = true", result[0].hasDeviceAdmin)
    }
}
