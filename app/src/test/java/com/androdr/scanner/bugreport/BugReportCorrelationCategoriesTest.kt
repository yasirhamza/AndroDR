package com.androdr.scanner.bugreport

import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.rawFile
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import com.androdr.scanner.BugReportHooks
import com.androdr.scanner.WriterFixture
import com.androdr.sigma.BugReportRecordBuilders
import com.androdr.sigma.SigmaCorrelationEngine
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleParser
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.Before
import org.junit.runner.RunWith
import org.robolectric.ParameterizedRobolectricTestRunner
import java.util.TimeZone

/**
 * Ruling R26 (review I-1): facts must yield exactly the legacy timeline's atoms. A bug report's
 * install-history UPDATE is not an install, and a system-UID AppOps op never had a timeline row, so
 * neither is a correlation atom. Driven through the real `InstallTimeModule` and `AppOpsModule`
 * output, stored and correlated by the import session's finishing transaction.
 *
 * Ruling R27 (TZ-1): both modules read the report's wall-clock times with the import's one clock
 * (the capture zone, here Asia/Qatar from `persist.sys.timezone`), so every case gives the same
 * outcome whatever the analyzing device's zone: the class runs under three JVM default zones.
 */
@RunWith(ParameterizedRobolectricTestRunner::class)
class BugReportCorrelationCategoriesTest(private val jvmZone: String) {
    private val w = WriterFixture()
    private val zone: TimeZone = TimeZone.getDefault()
    private val clock = DumpsysClock.fromSystemProperties("[persist.sys.timezone]: [Asia/Qatar]")

    @Before fun setUp() = TimeZone.setDefault(TimeZone.getTimeZone(jvmZone))

    @After fun tearDown() {
        w.close()
        TimeZone.setDefault(zone)
    }

    private fun atom(name: String) = SigmaRuleParser.parse(rawFile("$name.yml").readText())!!
    private fun corr(name: String) = SigmaRuleParser.parseCorrelation(rawFile("$name.yml").readText())

    private val engine = SigmaRuleEngine(mockk(relaxed = true)).apply {
        setRemoteRules(listOf(
            atom("sigma_androdr_atom_permission_use"), atom("sigma_androdr_atom_package_install"),
            atom("sigma_androdr_atom_device_admin_grant"), atom("sigma_androdr_atom_dns_lookup"),
        ))
        loadCorrelationRules(listOf(
            corr("sigma_androdr_corr_002_install_then_permission"),
            corr("sigma_androdr_corr_004_surveillance_burst"),
        ))
    }

    private val resolver = mockk<IndicatorResolver> { every { isKnownBadPackage(any()) } returns null }

    /** Imports [packages] (a `dumpsys package` section) and [appops] (a `dumpsys appops` section). */
    private fun import(id: Long, packages: String, appops: String) = runBlocking {
        val installs = InstallTimeModule()
        val ops = AppOpsModule().analyze(appops, resolver, DeviceIdentity.UNKNOWN, clock)
        val scan = w.scan(id, TelemetrySource.BUGREPORT_IMPORT)
        val hooks = BugReportHooks(scan, engine, SigmaCorrelationEngine(), emptyMap())
        val s = w.writer.begin(scan, liveEvents = false, hooks)
        s.append("appops_audit", TelemetrySource.BUGREPORT_IMPORT, CAPTURED,
            BugReportRecordBuilders.generic(ops.telemetry))
        s.append(BugReportRecordBuilders.PACKAGE_INSTALL_HISTORY, TelemetrySource.BUGREPORT_IMPORT, CAPTURED,
            BugReportRecordBuilders.packageInstallHistory(installs.parseHistory(packages, CAPTURED, clock)))
        s.finish()
        // C3: the modules write no rows (R17's row-to-fact pairing is moot): every event is its fact.
        val moduleRows = w.f.db.forensicTimelineEventDao().getAllForExport()
            .filter { it.scanResultId == id && it.kind == "event" && it.ruleId.isEmpty() }
        assertTrue("module rows: $moduleRows", moduleRows.isEmpty())
    }

    private fun signals(ruleId: String): Long =
        w.count("SELECT COUNT(*) FROM forensic_timeline WHERE kind = 'signal' AND ruleId = '$ruleId'")

    @Test
    fun `a Play auto-update followed by a camera access 20 minutes later fires no corr-002`() {
        import(1L, packages = """
            Package [com.example.chat] (ab12cd):
              versionCode=900 minSdk=26 targetSdk=34
              firstInstallTime=2024-01-01 08:00:00
              lastUpdateTime=2026-03-27 09:00:00
        """.trimIndent(), appops = """
            Uid 10150:
              Package com.example.chat:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 09:20:00
        """.trimIndent())

        assertEquals("an update is not an install", 0L, signals("androdr-corr-002"))
        assertEquals("the update is stored, under its own category", 1L,
            w.count("SELECT COUNT(*) FROM telemetry_record WHERE category = 'package_update'"))
    }

    @Test
    fun `system-UID ops captured close together fire no corr-004`() {
        import(2L, packages = "", appops = """
            Uid 1000:
              Package android:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 09:00:00
                RECORD_AUDIO (allow):
                  Access: [fg-s] 2026-03-27 09:01:00
                READ_CONTACTS (allow):
                  Access: [fg-s] 2026-03-27 09:02:00
        """.trimIndent())

        assertEquals("system ops are not permission_use atoms", 0L, signals("androdr-corr-004"))
        assertEquals("all three are stored verbatim", 3L,
            w.count("SELECT COUNT(*) FROM telemetry_record WHERE category = 'system_permission_use'"))
    }

    @Test
    fun `a sideloaded install followed by permission use still fires corr-002`() {
        import(3L, packages = """
            Package [com.evil.app] (ef34gh):
              versionCode=1 minSdk=26 targetSdk=34
              firstInstallTime=2026-03-27 09:00:00
              lastUpdateTime=2026-03-27 09:00:00
        """.trimIndent(), appops = """
            Uid 10200:
              Package com.evil.app:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 09:20:00
        """.trimIndent())

        assertEquals("the positive control fires once", 1L, signals("androdr-corr-002"))
    }

    @Test
    fun `three non-system ops close together still fire corr-004`() {
        import(4L, packages = "", appops = """
            Uid 10300:
              Package com.spy.app:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 09:00:00
                RECORD_AUDIO (allow):
                  Access: [fg-s] 2026-03-27 09:01:00
                READ_CONTACTS (allow):
                  Access: [fg-s] 2026-03-27 09:02:00
        """.trimIndent())

        assertEquals(1L, signals("androdr-corr-004"))
        assertEquals("each op binds once, as its fact", listOf(1, 1, 1),
            w.f.db.openHelper.readableDatabase.query("SELECT kind FROM signal_member").use { c ->
                generateSequence { if (c.moveToNext()) c.getInt(0) else null }.toList()
            })
    }

    companion object {
        private const val CAPTURED = 1_774_605_600_000L

        @JvmStatic
        @ParameterizedRobolectricTestRunner.Parameters(name = "JVM zone {0}")
        fun zones(): List<Array<Any>> = listOf("UTC", "Asia/Qatar", "America/New_York").map { arrayOf<Any>(it) }
    }
}
