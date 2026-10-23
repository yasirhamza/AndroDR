package com.androdr.scanner

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.OemPrefixResolver
import com.androdr.scanner.bugreport.AccessibilityModule
import com.androdr.scanner.bugreport.ActivityModule
import com.androdr.scanner.bugreport.AdbKeysModule
import com.androdr.scanner.bugreport.AppOpsModule
import com.androdr.scanner.bugreport.BatteryDailyModule
import com.androdr.scanner.bugreport.BugreportModule
import com.androdr.scanner.bugreport.DbInfoModule
import com.androdr.scanner.bugreport.GetpropParser
import com.androdr.scanner.bugreport.InstallTimeModule
import com.androdr.scanner.bugreport.PlatformCompatModule
import com.androdr.scanner.bugreport.ReceiverModule
import com.androdr.scanner.bugreport.TombstoneParser
import com.androdr.scanner.bugreport.WakelockParser
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.toFieldMap
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Runs the real [BugReportAnalyzer] on a minimal bug report that has every section the typed
 * modules read, and checks the typed bundle is complete (telemetry-store spec 5.3).
 */
@RunWith(RobolectricTestRunner::class)
class BugReportTypedRecordsTest {

    private lateinit var resolver: IndicatorResolver
    private lateinit var analyzer: BugReportAnalyzer

    private fun fixtureText(): String {
        val name = "fixtures/bugreport-minimal-all-sections.txt"
        return listOf(File("src/test/resources/$name"), File("app/src/test/resources/$name"))
            .first { it.isFile }.readText()
    }

    private fun zipBytes(text: String): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            zip.putNextEntry(ZipEntry("dumpstate.txt"))
            zip.write(text.toByteArray())
            zip.closeEntry()
        }
        return out.toByteArray()
    }

    @Before
    fun setUp() {
        resolver = mockk(relaxed = true)
        every { resolver.isKnownBadPackage(any()) } returns null
        val bytes = zipBytes(fixtureText())
        val contentResolver = mockk<ContentResolver>()
        every { contentResolver.openInputStream(any()) } answers { ByteArrayInputStream(bytes) }
        val context = mockk<Context>(relaxed = true)
        every { context.contentResolver } returns contentResolver
        val oem = mockk<OemPrefixResolver>(relaxed = true)
        val modules: Set<BugreportModule> = setOf(
            AccessibilityModule(oem), ActivityModule(oem), AdbKeysModule(), AppOpsModule(),
            BatteryDailyModule(), DbInfoModule(), PlatformCompatModule(), ReceiverModule(oem),
        )
        analyzer = BugReportAnalyzer(
            context, resolver, modules, SigmaRuleEngine(mockk<Context>(relaxed = true)),
            TombstoneParser(), WakelockParser(), GetpropParser(),
        )
    }

    private fun analyze() = runBlocking { analyzer.analyze(Uri.parse("content://test/bugreport.zip")) }

    @Test
    fun `every typed list is non-empty`() {
        val b = analyze().telemetryBundle
        assertTrue("tombstones", b.tombstoneEvents.isNotEmpty())
        assertTrue("wakelocks", b.wakelockAcquisitions.isNotEmpty())
        assertTrue("battery", b.batteryDailyEvents.isNotEmpty())
        assertTrue("install history", b.packageInstallHistory.isNotEmpty())
        assertTrue("platform compat", b.platformCompatChanges.isNotEmpty())
        assertTrue("db info", b.databasePathObservations.isNotEmpty())
        assertTrue("system properties", b.systemPropertySnapshots.isNotEmpty())
    }

    @Test
    fun `db info records carry db_path and recent_query_count`() {
        val maps = analyze().telemetryBundle.databasePathObservations.map { it.toFieldMap() }
        val alpha = maps.first { it["package_name"] == "com.example.alpha" }
        assertEquals("/data/user/0/com.example.alpha/databases/app.db", alpha["db_path"])
        assertEquals(alpha["db_path"], alpha["file_path"])
        assertEquals(2, alpha["recent_query_count"])
        assertEquals(1, maps.first { it["package_name"] == "com.example.beta" }["recent_query_count"])
    }

    @Test
    fun `install history carries version code and install time`() {
        val history = analyze().telemetryBundle.packageInstallHistory
        val alpha = history.first { it.packageName == "com.example.alpha" }
        assertEquals(100L, alpha.versionCode)
        assertEquals(
            LocalDateTime.of(2026, 3, 1, 8, 0, 0).toInstant(ZoneOffset.UTC).toEpochMilli(),
            alpha.timestamp,
        )
        assertEquals(2, history.size)
    }

    @Test
    fun `platform compat parses enabled`() {
        val compat = analyze().telemetryBundle.platformCompatChanges
        assertTrue(compat.first { it.changeId == "168419799" }.enabled)
        assertFalse(compat.first { it.changeId == "999999999" }.enabled)
    }

    @Test
    fun `wakelock time is taken from the dumpstate header`() {
        val header = LocalDateTime.of(2026, 3, 28, 10, 15, 30).toInstant(ZoneOffset.UTC).toEpochMilli()
        val wakelock = analyze().telemetryBundle.wakelockAcquisitions.single()
        assertEquals(header - (2 * 3_600_000L + 15 * 60_000L + 30_000L), wakelock.acquiredAt)
    }

    @Test
    fun `no generic record remains for typed services`() = runBlocking {
        val text = fixtureText()
        fun section(name: String) = text.substringAfter("------ SERVICE $name ------")
            .substringBefore("------ SERVICE ")
        listOf(
            BatteryDailyModule() to "batterystats", DbInfoModule() to "dbinfo",
            PlatformCompatModule() to "platform_compat",
        ).forEach { (module, name) ->
            val result = module.analyze(section(name), resolver, DeviceIdentity.UNKNOWN)
            assertTrue("${module.javaClass.simpleName} generic telemetry", result.telemetry.isEmpty())
            assertTrue(result.telemetryService !in setOf("dbinfo_audit", "platform_compat_audit"))
        }
    }

    @Test
    fun `install history matches the InstallTimeModule timeline rows`() {
        val section = fixtureText().substringAfter("------ SERVICE package ------")
            .substringBefore("------ SERVICE ")
        val rows = InstallTimeModule().parseSection(section)
        val history = InstallTimeModule().parseHistory(section, capturedAt = 1L)
        assertEquals(
            rows.map { it.packageName to it.startTimestamp },
            history.map { it.packageName to it.timestamp },
        )
    }
}
