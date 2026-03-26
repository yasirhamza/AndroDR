package com.androdr.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import com.androdr.data.model.RiskLevel
import com.androdr.ioc.BadPackageInfo
import com.androdr.ioc.IocResolver
import com.androdr.ioc.KnownAppResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AppScannerTest {

    private val mockContext: Context = mockk(relaxed = true)
    private val mockPm: PackageManager = mockk(relaxed = true)
    private val mockIocResolver: IocResolver = mockk()
    private val mockKnownAppResolver: KnownAppResolver = mockk()
    private lateinit var scanner: AppScanner

    @Before
    fun setUp() {
        every { mockContext.packageManager } returns mockPm
        every { mockIocResolver.isKnownBadPackage(any()) } returns null
        every { mockKnownAppResolver.lookup(any()) } returns null  // default: unknown app
        scanner = AppScanner(mockContext, mockIocResolver, mockKnownAppResolver)
    }

    private fun makePackageInfo(
        packageName: String,
        permissions: Array<String> = emptyArray(),
        isSystem: Boolean = false,
        installer: String? = "com.android.vending"
    ): PackageInfo {
        val appInfo = ApplicationInfo()
        appInfo.flags = if (isSystem) ApplicationInfo.FLAG_SYSTEM else 0

        val pkgInfo = PackageInfo()
        pkgInfo.packageName = packageName
        pkgInfo.applicationInfo = appInfo
        pkgInfo.requestedPermissions = permissions.ifEmpty { null }

        every { mockPm.getApplicationLabel(appInfo) } returns packageName
        @Suppress("DEPRECATION")
        every { mockPm.getInstallerPackageName(packageName) } returns installer

        return pkgInfo
    }

    // ── IOC database matching ─────────────────────────────────────────────────

    @Test
    fun `known malware package is flagged as CRITICAL`() = runTest {
        val pkgInfo = makePackageInfo("com.flexispy.android")
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
        every { mockIocResolver.isKnownBadPackage("com.flexispy.android") } returns BadPackageInfo(
            packageName = "com.flexispy.android",
            name = "FlexiSPY",
            category = "STALKERWARE",
            severity = "CRITICAL",
            description = "Known stalkerware."
        )

        val results = scanner.scan()

        assertEquals(1, results.size)
        assertEquals(RiskLevel.CRITICAL, results[0].riskLevel)
        assertTrue(results[0].isKnownMalware)
    }

    // ── Permission combination scoring ────────────────────────────────────────

    @Test
    fun `four or more surveillance permissions yields CRITICAL risk for sideloaded app`() = runTest {
        val perms = arrayOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.ACCESS_FINE_LOCATION"
        )
        val pkgInfo = makePackageInfo("com.suspicious.app", permissions = perms, installer = null)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertEquals(1, results.size)
        assertEquals(RiskLevel.CRITICAL, results[0].riskLevel)
        assertEquals(4, results[0].dangerousPermissions.size)
    }

    @Test
    fun `two or three surveillance permissions yields HIGH risk for sideloaded app`() = runTest {
        val perms = arrayOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS"
        )
        val pkgInfo = makePackageInfo("com.moderate.app", permissions = perms, installer = "com.unknown.source")
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertEquals(1, results.size)
        assertEquals(RiskLevel.HIGH, results[0].riskLevel)
    }

    @Test
    fun `trusted store app with many surveillance permissions is not flagged`() = runTest {
        val perms = arrayOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CAMERA"
        )
        // Simulate WhatsApp-like app from Play Store — should not be scored for permissions
        val playPkg = makePackageInfo("com.whatsapp", permissions = perms, installer = "com.android.vending")
        // Simulate Signal-like app from Samsung Store — should also not be scored
        val samsungPkg = makePackageInfo("org.signal.app", permissions = perms,
            installer = "com.sec.android.app.samsungapps")
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(playPkg, samsungPkg)

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    @Test
    fun `one surveillance permission is not flagged`() = runTest {
        val perms = arrayOf("android.permission.RECORD_AUDIO")
        val pkgInfo = makePackageInfo("com.voice.recorder", permissions = perms)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    @Test
    fun `non-surveillance permissions are not counted`() = runTest {
        val perms = arrayOf(
            "android.permission.INTERNET",
            "android.permission.VIBRATE",
            "android.permission.RECEIVE_BOOT_COMPLETED"
        )
        val pkgInfo = makePackageInfo("com.normal.app", permissions = perms)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    // ── Sideload detection ────────────────────────────────────────────────────

    @Test
    fun `sideloaded app is flagged as MEDIUM with isSideloaded true`() = runTest {
        val pkgInfo = makePackageInfo("com.sideloaded.app", installer = "com.unknown.source")
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertEquals(1, results.size)
        assertEquals(RiskLevel.MEDIUM, results[0].riskLevel)
        assertTrue(results[0].isSideloaded)
    }

    @Test
    fun `Play Store installed app is not flagged as sideloaded`() = runTest {
        val pkgInfo = makePackageInfo("com.legit.app", installer = "com.android.vending")
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    @Test
    fun `Samsung Galaxy Store installed app is not flagged as sideloaded`() = runTest {
        val pkgInfo = makePackageInfo("com.samsung.app", installer = "com.sec.android.app.samsungapps")
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    @Test
    fun `OEM-prefixed user app with null installer is not flagged as sideloaded`() = runTest {
        // Samsung TV Plus / Samsung Kids are non-system apps that may have null installer
        // (OEM provisioned) but belong to the Samsung namespace and must not be flagged.
        val pkgInfo = makePackageInfo("com.samsung.android.tvplus", isSystem = false, installer = null)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
        every { mockKnownAppResolver.lookup("com.samsung.android.tvplus") } returns KnownAppEntry(
            packageName = "com.samsung.android.tvplus", displayName = "Samsung TV Plus",
            category = KnownAppCategory.OEM, sourceId = "bundled", fetchedAt = 0
        )

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    @Test
    fun `Samsung ecosystem installer is treated as trusted`() = runTest {
        // e.g. Galaxy Buds plugin installed by Watch Manager
        val pkgInfo = makePackageInfo("com.samsung.accessory.buds",
            installer = "com.samsung.android.app.watchmanager")
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    @Test
    fun `system app with unknown prefix is not scored for permission combinations`() = runTest {
        // A pre-installed system app with many permissions (e.g. Amazon pre-install) should only
        // trigger the firmware-implant finding, not additionally be scored as CRITICAL.
        val perms = arrayOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.ACCESS_FINE_LOCATION"
        )
        val pkgInfo = makePackageInfo("com.suspicious.systemagent", permissions = perms, isSystem = true)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertEquals(1, results.size)
        // firmware-implant check fires at HIGH — permission scoring must NOT elevate this to CRITICAL
        assertEquals(RiskLevel.HIGH, results[0].riskLevel)
        assertTrue(results[0].reasons.any { it.contains("system-level privileges") })
    }

    @Test
    fun `installer unknown (null) is treated as sideloaded`() = runTest {
        val pkgInfo = makePackageInfo("com.mystery.app", installer = null)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertEquals(1, results.size)
        assertTrue(results[0].isSideloaded)
    }

    // ── Anomalous system app detection ────────────────────────────────────────

    @Test
    fun `system app with unknown package prefix is flagged as HIGH`() = runTest {
        val pkgInfo = makePackageInfo("com.suspicious.systemagent", isSystem = true)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertEquals(1, results.size)
        assertEquals(RiskLevel.HIGH, results[0].riskLevel)
        assertTrue(results[0].reasons.any { it.contains("system-level privileges") })
    }

    @Test
    fun `system app with known OEM prefix is not flagged`() = runTest {
        val pkgInfo = makePackageInfo("com.android.settings", isSystem = true)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
        every { mockKnownAppResolver.lookup("com.android.settings") } returns KnownAppEntry(
            packageName = "com.android.settings", displayName = "Settings",
            category = KnownAppCategory.AOSP, sourceId = "bundled", fetchedAt = 0
        )

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    // ── Risk level precedence ─────────────────────────────────────────────────

    @Test
    fun `IOC hit takes precedence over permission score for risk level`() = runTest {
        val perms = arrayOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS"
        )
        val pkgInfo = makePackageInfo("com.evil.known", permissions = perms)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
        every { mockIocResolver.isKnownBadPackage("com.evil.known") } returns BadPackageInfo(
            packageName = "com.evil.known",
            name = "EvilApp",
            category = "SPYWARE",
            severity = "CRITICAL",
            description = "Known spyware."
        )

        val results = scanner.scan()

        assertEquals(RiskLevel.CRITICAL, results[0].riskLevel)
        assertTrue(results[0].isKnownMalware)
    }

    // ── Results ordering ──────────────────────────────────────────────────────

    @Test
    fun `results are sorted by risk level descending`() = runTest {
        val criticalPerms = arrayOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.ACCESS_FINE_LOCATION"
        )
        val highPerms = arrayOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS"
        )

        val criticalPkg = makePackageInfo("com.critical.app", permissions = criticalPerms,
            installer = "com.random.store")
        val highPkg = makePackageInfo("com.high.app", permissions = highPerms,
            installer = "com.other.store")
        val sideloadedPkg = makePackageInfo("com.medium.app", installer = "com.random.store")

        every { mockPm.getInstalledPackages(any<Int>()) } returns
            listOf(sideloadedPkg, highPkg, criticalPkg)

        val results = scanner.scan()

        assertEquals(3, results.size)
        assertEquals(RiskLevel.CRITICAL, results[0].riskLevel)
        assertEquals(RiskLevel.HIGH, results[1].riskLevel)
        assertEquals(RiskLevel.MEDIUM, results[2].riskLevel)
    }

    // ── Clean app ─────────────────────────────────────────────────────────────

    @Test
    fun `clean app with no risk factors is not included in results`() = runTest {
        val pkgInfo = makePackageInfo("com.safe.app")
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertFalse(results.any { it.packageName == "com.safe.app" })
    }

    @Test
    fun `empty package list returns empty results`() = runTest {
        every { mockPm.getInstalledPackages(any<Int>()) } returns emptyList()

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    @Test
    fun `PackageManager exception returns empty results`() = runTest {
        every { mockPm.getInstalledPackages(any<Int>()) } throws SecurityException("No permission")

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    // ── Known-app DB integration ──────────────────────────────────────────────

    @Test
    fun `OEM DB hit suppresses sideload flag for user app with null installer`() = runTest {
        val pkgInfo = makePackageInfo("com.sec.android.app.sbrowser", installer = null)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
        every { mockKnownAppResolver.lookup("com.sec.android.app.sbrowser") } returns KnownAppEntry(
            packageName = "com.sec.android.app.sbrowser", displayName = "Samsung Internet",
            category = KnownAppCategory.OEM, sourceId = "uad_ng", fetchedAt = 0
        )

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    @Test
    fun `OEM DB hit suppresses firmware-implant flag for system app`() = runTest {
        val pkgInfo = makePackageInfo("com.sec.android.app.launcher", isSystem = true)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
        every { mockKnownAppResolver.lookup("com.sec.android.app.launcher") } returns KnownAppEntry(
            packageName = "com.sec.android.app.launcher", displayName = "Samsung Launcher",
            category = KnownAppCategory.OEM, sourceId = "uad_ng", fetchedAt = 0
        )

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }

    @Test
    fun `USER_APP DB hit from untrusted source raises impersonation HIGH`() = runTest {
        val pkgInfo = makePackageInfo("com.whatsapp", installer = null)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
        every { mockKnownAppResolver.lookup("com.whatsapp") } returns KnownAppEntry(
            packageName = "com.whatsapp", displayName = "WhatsApp",
            category = KnownAppCategory.USER_APP, sourceId = "plexus", fetchedAt = 0
        )

        val results = scanner.scan()

        assertEquals(1, results.size)
        assertEquals(RiskLevel.HIGH, results[0].riskLevel)
        assertTrue(results[0].reasons.any { it.contains("impersonation") })
    }

    @Test
    fun `USER_APP DB hit from trusted store raises no flag`() = runTest {
        val pkgInfo = makePackageInfo("com.whatsapp", installer = "com.android.vending")
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)
        every { mockKnownAppResolver.lookup("com.whatsapp") } returns KnownAppEntry(
            packageName = "com.whatsapp", displayName = "WhatsApp",
            category = KnownAppCategory.USER_APP, sourceId = "plexus", fetchedAt = 0
        )

        val results = scanner.scan()

        assertTrue(results.isEmpty())
    }
}
