package com.androdr.scanner

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.content.pm.ActivityInfo
import android.content.pm.ProviderInfo
import android.content.res.Resources
import com.androdr.R
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import com.androdr.ioc.KnownAppResolver
import com.androdr.ioc.OemPrefixResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class AppScannerTelemetryTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var context: Context
    private lateinit var pm: PackageManager
    private lateinit var knownAppResolver: KnownAppResolver
    private lateinit var oemPrefixResolver: OemPrefixResolver
    private lateinit var scanner: AppScanner

    private fun buildSyntheticApk(name: String, entries: List<String>): File {
        val file = tempFolder.newFile(name)
        ZipOutputStream(FileOutputStream(file)).use { zip ->
            for (entry in entries) {
                zip.putNextEntry(ZipEntry(entry))
                zip.write(byteArrayOf(0)) // placeholder body so the entry is well-formed
                zip.closeEntry()
            }
        }
        return file
    }

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
        receivers: Array<ActivityInfo>? = null,
        firstInstallTime: Long = 0L,
        lastUpdateTime: Long = 0L
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
            this.firstInstallTime = firstInstallTime
            this.lastUpdateTime = lastUpdateTime
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

    // ── 4. Unconditional (AOSP) OEM prefix treated as known OEM ─────────────
    // NOTE: Samsung-specific prefixes were previously tested here, but
    // under #90 (device-conditional allowlist) the Samsung block only
    // applies when Build.MANUFACTURER matches "samsung". In a unit test
    // JVM that field is "unknown", so this now exercises an unconditional
    // AOSP prefix, which is the correct cross-device behavior.

    @Test
    fun `AOSP package prefix is treated as known OEM app`() = runTest {
        val pkg = buildPackageInfo(
            pkgName = "com.android.chrome",
            installerPkg = null
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        val telemetry = result[0]
        assertTrue("Expected isKnownOemApp = true", telemetry.isKnownOemApp)
        assertFalse("Expected isSideloaded = false for AOSP OEM app", telemetry.isSideloaded)
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

    // ── 8. Install-time fields propagate to telemetry and field map ─────────

    @Test
    fun `firstInstallTime and lastUpdateTime propagate to telemetry and field map`() = runTest {
        val firstInstall = 1_700_000_000_000L
        val lastUpdate = 1_710_000_000_000L
        val pkg = buildPackageInfo(
            pkgName = "com.example.installtime",
            installerPkg = "com.android.vending",
            firstInstallTime = firstInstall,
            lastUpdateTime = lastUpdate
        )
        installPackages(pkg)

        val result = scanner.collectTelemetry()

        assertEquals(1, result.size)
        val telemetry = result[0]
        assertEquals(firstInstall, telemetry.firstInstallTime)
        assertEquals(lastUpdate, telemetry.lastUpdateTime)

        val fieldMap = telemetry.toFieldMap()
        assertEquals(firstInstall, fieldMap["first_install_time"])
        assertEquals(lastUpdate, fieldMap["last_update_time"])
    }

    // ── 9. extractComponentClassNames ────────────────────────────────────────

    @Test
    fun `extractComponentClassNames returns deduped sorted class names from all four component kinds`() {
        val pkgInfo = PackageInfo().apply {
            services = arrayOf(
                ServiceInfo().apply { name = "com.outlogic.collector.GeoSyncService" },
                ServiceInfo().apply { name = "com.example.legit.NormalService" }
            )
            receivers = arrayOf(
                ActivityInfo().apply { name = "com.outlogic.collector.WakeReceiver" }
            )
            activities = arrayOf(
                ActivityInfo().apply { name = "com.example.legit.MainActivity" },
                ActivityInfo().apply { name = "com.example.legit.MainActivity" } // dup
            )
            providers = arrayOf(
                ProviderInfo().apply { name = "com.example.legit.SettingsProvider" }
            )
        }

        val result = scanner.extractComponentClassNames(pkgInfo)

        assertEquals(
            listOf(
                "com.example.legit.MainActivity",
                "com.example.legit.NormalService",
                "com.example.legit.SettingsProvider",
                "com.outlogic.collector.GeoSyncService",
                "com.outlogic.collector.WakeReceiver"
            ),
            result
        )
    }

    @Test
    fun `extractComponentClassNames returns emptyList when all four arrays are null`() {
        val pkgInfo = PackageInfo().apply {
            services = null
            receivers = null
            activities = null
            providers = null
        }
        assertEquals(emptyList<String>(), scanner.extractComponentClassNames(pkgInfo))
    }

    @Test
    fun `extractComponentClassNames truncates to MAX_COMPONENTS_PER_APP and keeps lexicographically-first entries`() {
        val many = (1..2000).map { ActivityInfo().apply { name = "com.example.A$it" } }.toTypedArray()
        val pkgInfo = PackageInfo().apply { activities = many; services = null; receivers = null; providers = null }
        val result = scanner.extractComponentClassNames(pkgInfo)
        assertEquals(1024, result.size)
        // sort-then-take guarantees lexicographic stability — the smallest name survives.
        // ("com.example.A1" lex-precedes "com.example.A1000", "A1001", ..., as well as "A2".)
        assertEquals("com.example.A1", result.first())
    }

    // ── 10. extractNativeLibFileNames ────────────────────────────────────────

    @Test
    fun `extractNativeLibFileNames returns deduped leaf filenames across ABIs`() {
        val apk = buildSyntheticApk("test.apk", listOf(
            "AndroidManifest.xml",
            "classes.dex",
            "lib/arm64-v8a/libxmode.so",
            "lib/arm64-v8a/libcollector.so",
            "lib/x86_64/libxmode.so",                 // dup of arm64-v8a leaf
            "lib/armeabi-v7a/libcollector.so",        // dup of arm64-v8a leaf
            "lib/arm64-v8a/libunique.so",
            "res/values/strings.xml"
        ))
        val appInfo = ApplicationInfo().apply { publicSourceDir = apk.absolutePath }

        val result = scanner.extractNativeLibFileNames(appInfo)

        assertEquals(listOf("libcollector.so", "libunique.so", "libxmode.so"), result)
    }

    @Test
    fun `extractNativeLibFileNames returns emptyList for a non-existent path`() {
        val appInfo = ApplicationInfo().apply { publicSourceDir = "/does/not/exist.apk" }
        assertEquals(emptyList<String>(), scanner.extractNativeLibFileNames(appInfo))
    }

    @Test
    fun `extractNativeLibFileNames returns emptyList for a corrupt zip`() {
        val bogus = tempFolder.newFile("bogus.apk")
        bogus.writeText("not a zip file")
        val appInfo = ApplicationInfo().apply { publicSourceDir = bogus.absolutePath }
        assertEquals(emptyList<String>(), scanner.extractNativeLibFileNames(appInfo))
    }

    @Test
    fun `extractNativeLibFileNames truncates to MAX_NATIVE_LIBS_PER_APP and keeps lexicographically-first entries`() {
        val entries = (1..400).map { "lib/arm64-v8a/lib$it.so" }
        val apk = buildSyntheticApk("big.apk", entries)
        val appInfo = ApplicationInfo().apply { publicSourceDir = apk.absolutePath }
        val result = scanner.extractNativeLibFileNames(appInfo)
        assertEquals(256, result.size)
        // sort-then-take guarantees lexicographic stability — "lib1.so" precedes
        // "lib100.so" etc.
        assertEquals("lib1.so", result.first())
    }
}
