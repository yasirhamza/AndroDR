package com.androdr.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import com.androdr.data.model.RiskLevel
import com.androdr.ioc.BadPackageInfo
import com.androdr.ioc.IocDatabase
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
    private val mockIocDatabase: IocDatabase = mockk()
    private lateinit var scanner: AppScanner

    @Before
    fun setUp() {
        every { mockContext.packageManager } returns mockPm
        every { mockIocDatabase.isKnownBadPackage(any()) } returns null
        scanner = AppScanner(mockContext, mockIocDatabase)
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
        every { mockIocDatabase.isKnownBadPackage("com.flexispy.android") } returns BadPackageInfo(
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
    fun `four or more surveillance permissions yields CRITICAL risk`() = runTest {
        val perms = arrayOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.ACCESS_FINE_LOCATION"
        )
        val pkgInfo = makePackageInfo("com.suspicious.app", permissions = perms)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertEquals(1, results.size)
        assertEquals(RiskLevel.CRITICAL, results[0].riskLevel)
        assertEquals(4, results[0].dangerousPermissions.size)
    }

    @Test
    fun `two or three surveillance permissions yields HIGH risk`() = runTest {
        val perms = arrayOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS"
        )
        val pkgInfo = makePackageInfo("com.moderate.app", permissions = perms)
        every { mockPm.getInstalledPackages(any<Int>()) } returns listOf(pkgInfo)

        val results = scanner.scan()

        assertEquals(1, results.size)
        assertEquals(RiskLevel.HIGH, results[0].riskLevel)
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
        every { mockIocDatabase.isKnownBadPackage("com.evil.known") } returns BadPackageInfo(
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

        val criticalPkg = makePackageInfo("com.critical.app", permissions = criticalPerms)
        val highPkg = makePackageInfo("com.high.app", permissions = highPerms,
            installer = "com.android.vending")
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
}
