package com.androdr.scanner

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import com.androdr.data.model.PackageHistoryEventType
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
import com.androdr.sigma.toFieldMap
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
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
        analyzer = buildAnalyzer(fixtureText(), defaultModules())
    }

    private fun defaultModules(battery: BatteryDailyModule = BatteryDailyModule()): Set<BugreportModule> {
        val oem = mockk<OemPrefixResolver>(relaxed = true)
        return setOf(
            AccessibilityModule(oem), ActivityModule(oem), AdbKeysModule(), AppOpsModule(),
            battery, DbInfoModule(), PlatformCompatModule(), ReceiverModule(oem),
        )
    }

    private fun buildAnalyzer(text: String, modules: Set<BugreportModule>): BugReportAnalyzer {
        val bytes = zipBytes(text)
        val contentResolver = mockk<ContentResolver>()
        every { contentResolver.openInputStream(any()) } answers { ByteArrayInputStream(bytes) }
        val context = mockk<Context>(relaxed = true)
        every { context.contentResolver } returns contentResolver
        return BugReportAnalyzer(
            context, resolver, modules,
            TombstoneParser(), WakelockParser(), GetpropParser(),
        )
    }

    private fun analyze(a: BugReportAnalyzer = analyzer) =
        runBlocking { a.analyze(Uri.parse("content://test/bugreport.zip")) }

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
    fun `install history is the exact INSTALL and UPDATE list`() {
        fun ms(m: Int, d: Int, h: Int, mi: Int) =
            LocalDateTime.of(2026, m, d, h, mi, 0).toInstant(ZoneOffset.UTC).toEpochMilli()
        val history = analyze().telemetryBundle.packageInstallHistory
        // beta's lastUpdateTime equals its firstInstallTime: the same instant, so no UPDATE.
        assertEquals(
            listOf(
                Triple("com.example.alpha", PackageHistoryEventType.INSTALL, ms(3, 1, 8, 0)),
                Triple("com.example.alpha", PackageHistoryEventType.UPDATE, ms(3, 20, 9, 0)),
                Triple("com.example.beta", PackageHistoryEventType.INSTALL, ms(3, 5, 12, 30)),
            ),
            history.map { Triple(it.packageName, it.eventType, it.timestamp) },
        )
        assertEquals(listOf(100L, 100L, 7L), history.map { it.versionCode })
    }

    @Test
    fun `platform compat parses enabled`() {
        val compat = analyze().telemetryBundle.platformCompatChanges
        assertEquals(true, compat.first { it.changeId == "168419799" }.enabled)
        assertEquals(false, compat.first { it.changeId == "999999999" }.enabled)
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
            history.filter { it.eventType == PackageHistoryEventType.INSTALL }
                .map { it.packageName to it.timestamp },
        )
    }

    @Test
    fun `wakelock time falls back to import time when the dumpstate header is missing`() {
        val noHeader = fixtureText().lines().filterNot { it.startsWith("== dumpstate:") }.joinToString("\n")
        val offset = 2 * 3_600_000L + 15 * 60_000L + 30_000L
        val before = System.currentTimeMillis()
        val wakelock = analyze(buildAnalyzer(noHeader, defaultModules()))
            .telemetryBundle.wakelockAcquisitions.single()
        val after = System.currentTimeMillis()
        assertTrue(wakelock.acquiredAt + offset in before..after)
    }

    @Test
    fun `a module that trips its record bound is reported in boundTrips`() {
        val tripping = buildAnalyzer(fixtureText(), defaultModules(BatteryDailyModule(maxRecords = 1)))
        val result = analyze(tripping)
        assertEquals(1, result.telemetryBundle.batteryDailyEvents.size)
        assertEquals(listOf("BatteryDailyModule: stopped at 1 records"), result.boundTrips)
        assertTrue(analyze().boundTrips.isEmpty())
    }
}
