package com.androdr.scanner

import android.net.Uri
import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.CveEntity
import com.androdr.data.model.DeviceTelemetry
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ProcessTelemetry
import com.androdr.data.model.ReceiverTelemetry
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.UsageEvent
import com.androdr.data.store.CanonicalJson
import com.androdr.data.store.StoreFixture
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.OemPrefixResolver
import com.androdr.scanner.bugreport.AccessibilityModule
import com.androdr.scanner.bugreport.ActivityModule
import com.androdr.scanner.bugreport.AdbKeysModule
import com.androdr.scanner.bugreport.AppOpsModule
import com.androdr.scanner.bugreport.ReceiverModule
import com.androdr.sigma.BugReportRecordBuilders
import com.androdr.sigma.CveEvidence
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.IntrusionLogRecordBuilders
import com.androdr.sigma.LiveRecordBuilders
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleParser
import com.androdr.sigma.StoreRecord
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayInputStream
import java.io.File
import java.lang.reflect.Modifier

/**
 * A8 D1 (ruling R21): every record builder's real output is storable and survives the store
 * unchanged. A live device with unpatched CVEs once put `CveEntity` objects into its field map, so
 * `CanonicalJson` threw and every live scan on such a device persisted nothing; a stored record
 * could not have carried them either, so CVE evidence would also have broken for stored records.
 *
 * Every builder method of [LiveRecordBuilders], [IntrusionLogRecordBuilders] and
 * [BugReportRecordBuilders] is exercised with non-empty data (a new builder fails [coverage] until
 * it is added here). For every record: `CanonicalJson.write` succeeds, the canonical form parses
 * back to the identical field map, and a round trip through the real store evaluates to the same
 * findings (evidence included) under every bundled rule.
 */
@RunWith(RobolectricTestRunner::class)
class RecordBuilderCanonicalTest {
    private val f = StoreFixture(recordSql = false)

    @After fun tearDown() = f.close()

    private val cves = listOf(
        CveEntity("CVE-2019-2215", "Binder use-after-free", "HIGH", "2019-11-05", "2021-11-03", true,
            "Android", "Kernel", 1L),
        CveEntity("CVE-2024-0001", "Some other flaw", "CRITICAL", "2024-12-05", "2024-12-10", true,
            "Google", "Android", 2L),
    )

    private fun device() = DeviceTelemetry(
        checkId = "device_posture", isTriggered = false, adbEnabled = true, devOptionsEnabled = true,
        unknownSourcesEnabled = true, screenLockEnabled = false, patchLevel = "2019-01-01", patchAgeDays = 2000,
        bootloaderUnlocked = true, wifiAdbEnabled = true, unpatchedCveCount = cves.size, unpatchedCves = cves,
        source = TelemetrySource.LIVE_SCAN,
    )

    private fun app() = AppTelemetry(
        packageName = "com.example.a", appName = "A", certHash = "ab12", certHashSha1 = "cd34", apkHash = "ef56",
        isSystemApp = false, fromTrustedStore = false, installer = "com.android.shell", isSideloaded = true,
        isKnownOemApp = false, permissions = listOf("android.permission.CAMERA"),
        requestedPermissions = listOf("android.permission.CAMERA", "android.permission.RECORD_AUDIO"),
        surveillancePermissionCount = 2, hasAccessibilityService = true, hasDeviceAdmin = true,
        hasBootReceiver = true, knownAppCategory = "USER_APP",
        servicePermissions = listOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
        receiverPermissions = listOf("android.permission.BIND_DEVICE_ADMIN"), hasLauncherActivity = false,
        firstInstallTime = 1_700_000_000_000L, lastUpdateTime = 1_700_000_100_000L,
        source = TelemetrySource.LIVE_SCAN, embeddedComponentClasses = listOf("com.x.Spy"),
        embeddedNativeLibs = listOf("libspy.so"), webapkScope = "https://example.com/",
    )

    private fun liveRecords(): Map<String, List<StoreRecord>> = mapOf(
        "apps" to LiveRecordBuilders.apps(listOf(app())),
        "device" to LiveRecordBuilders.device(listOf(device())),
        "processes" to LiveRecordBuilders.processes(
            listOf(ProcessTelemetry("com.example.a:svc", 10_123, "com.example.a", true, TelemetrySource.LIVE_SCAN))),
        "files" to LiveRecordBuilders.files(
            listOf(FileArtifactTelemetry("/data/local/tmp/x", true, 42L, 1_700_000_000_000L,
                TelemetrySource.LIVE_SCAN, true))),
        "accessibility" to LiveRecordBuilders.accessibility(
            listOf(AccessibilityTelemetry("com.example.a", "com.example.a/.Svc", false, true,
                TelemetrySource.LIVE_SCAN))),
        "receivers" to LiveRecordBuilders.receivers(
            listOf(ReceiverTelemetry("com.example.a", "android.provider.Telephony.SMS_RECEIVED",
                "com.example.a/.Rx", false, TelemetrySource.LIVE_SCAN))),
        "appOps" to LiveRecordBuilders.appOps(
            listOf(AppOpsTelemetry("com.example.a", "CAMERA", 1_700_000_000_000L, 1_699_000_000_000L, 3, false,
                TelemetrySource.LIVE_SCAN))),
        "usage" to LiveRecordBuilders.usage(
            listOf(UsageEvent(1_700_000_000_000L, "com.example.a", "A", "app_foreground",
                TelemetrySource.LIVE_SCAN, CAPTURED))),
        "dns" to LiveRecordBuilders.dns(
            listOf(DnsEvent(id = 7, timestamp = 1_700_000_000_000L, domain = "evil.example", appUid = 10_123,
                appName = "com.example.a", isBlocked = true, reason = "IOC: X"))),
    )

    /** The real intrusion-log analyzer's records, keyed by builder method. */
    private fun intrusionRecords(): Map<String, List<StoreRecord>> {
        val lines = listOf(
            """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.a",""" +
                """"hostname":"h1.example.com","ip_addresses":["/1.1.1.1"],"ip_addresses_count":1}}""",
            """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.a",""" +
                """"port":443,"ip_address":"/1.1.1.1"}}""",
            """{"security_event":{"event_id":2,"event_time":1787400350000,"tag":210002,"data":["id"]}}""",
        )
        val chunks = CollectingChunks()
        runBlocking {
            IntrusionLogAnalyzer(mockk(relaxed = true), mockk(relaxed = true)).analyzeEntries(
                sequenceOf("2026-08-22.txt" to ByteArrayInputStream(lines.joinToString("\n").toByteArray())),
                uidResolver = { 10_001 }, capturedAt = 1_787_400_400_000L, chunks = chunks,
            )
        }
        return mapOf(
            "importedDns" to chunks.records.getValue(LiveRecordBuilders.DNS_MONITOR),
            "network" to chunks.records.getValue(IntrusionLogRecordBuilders.NETWORK_MONITOR),
            "securityLog" to chunks.records.getValue(IntrusionLogRecordBuilders.SECURITY_LOG),
        )
    }

    /** The real bug-report analyzer's records over the all-sections fixture, keyed by builder method. */
    private fun bugReportRecords(): Map<String, List<StoreRecord>> {
        val result = runBlocking { BugReportFixtures.analyzer().analyze(mockk<Uri>(relaxed = true)) }
        val b = result.telemetryBundle
        return mapOf(
            "generic" to genericModuleRecords().values.flatten(),
            "tombstones" to BugReportRecordBuilders.tombstones(b.tombstoneEvents),
            "wakelocks" to BugReportRecordBuilders.wakelocks(b.wakelockAcquisitions),
            "batteryDaily" to BugReportRecordBuilders.batteryDaily(b.batteryDailyEvents),
            "packageInstallHistory" to BugReportRecordBuilders.packageInstallHistory(b.packageInstallHistory),
            "platformCompat" to BugReportRecordBuilders.platformCompat(b.platformCompatChanges),
            "databasePathObservations" to
                BugReportRecordBuilders.databasePathObservations(b.databasePathObservations),
            "systemProperties" to BugReportRecordBuilders.systemProperties(b.systemPropertySnapshots),
        )
    }

    /**
     * The real generic modules' field maps (the all-sections fixture yields none), each over a
     * section it parses, through [BugReportRecordBuilders.generic], keyed by service.
     */
    private fun genericModuleRecords(): Map<String, List<StoreRecord>> {
        val oem = mockk<OemPrefixResolver> { every { isOemPrefix(any(), any()) } returns false }
        val resolver = mockk<IndicatorResolver> { every { isKnownBadPackage(any()) } returns null }
        val runs = listOf(
            AccessibilityModule(oem) to """
                User state[userData:0 currentUser:0]:
                  isEnabled=1
                  Enabled services:
                    com.evil.spy/.SpyAccessibilityService
            """,
            AdbKeysModule() to """
                USB debugging: enabled
                Trusted keys:
                  QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFh user@workstation
            """,
            AppOpsModule() to """
                Uid 10150:
                  Package com.suspicious.installer:
                    REQUEST_INSTALL_PACKAGES (allow):
                      Access: [fg-s] 2026-03-27 14:30:00
            """,
            ReceiverModule(oem) to """
                Receiver Resolver Table:
                  Non-Data Actions:
                      android.provider.Telephony.SMS_RECEIVED:
                        12345 com.evil.sms/.SmsReceiver filter abcdef
                          Action: "android.provider.Telephony.SMS_RECEIVED"
            """,
            ActivityModule(oem) to """
                Activity Resolver Table:
                  Schemes:
                      http:
                        12345 com.evil.browser/.MainActivity filter abcdef
                          Action: "android.intent.action.VIEW"
            """,
        )
        return runs.associate { (module, section) ->
            val r = runBlocking { module.analyze(section.trimIndent(), resolver, DeviceIdentity.UNKNOWN) }
            assertTrue("${module.javaClass.simpleName} emits telemetry", r.telemetry.isNotEmpty())
            r.telemetryService to BugReportRecordBuilders.generic(r.telemetry)
        }
    }

    /** Public builder methods (those returning records) of [builder]. */
    private fun builderMethods(builder: Class<*>): Set<String> = builder.declaredMethods
        .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic && it.returnType == List::class.java }
        .map { it.name }.toSet()

    @Test
    fun `coverage - every builder method is exercised with non-empty records`() {
        for ((builder, covered) in listOf(
            LiveRecordBuilders::class.java to liveRecords(),
            IntrusionLogRecordBuilders::class.java to intrusionRecords(),
            BugReportRecordBuilders::class.java to bugReportRecords(),
        )) {
            assertEquals("${builder.simpleName}: every builder is exercised", builderMethods(builder), covered.keys)
            covered.forEach { (name, records) -> assertTrue("$name has records", records.isNotEmpty()) }
        }
        // The CVE case itself: the device record carries its CVEs.
        val device = liveRecords().getValue("device").single().fields
        assertEquals(2, (device["unpatched_cves"] as List<*>).size)
    }

    @Test
    fun `every record writes canonically and parses back to the identical field map`() {
        val all = liveRecords() + intrusionRecords().mapKeys { "il." + it.key } +
            bugReportRecords().mapKeys { "br." + it.key }
        for ((name, records) in all) {
            for (r in records) {
                val json = CanonicalJson.write(r.fields)
                assertEquals("$name round-trips through CanonicalJson", r.fields, CanonicalJson.parse(json))
            }
        }
    }

    @Test
    fun `live CVE findings render the same evidence as before`() {
        val rules = bundledRules()
        val findings = engine(rules).evaluateRecords(
            LiveRecordBuilders.DEVICE_AUDITOR, LiveRecordBuilders.device(listOf(device())), 0)
        val cve = findings.single { it.ruleId == "androdr-047" }
        assertEquals("2 Unpatched CVEs", cve.title)
        assertEquals(
            Evidence.CveList(
                cves = listOf(
                    CveEvidence("CVE-2019-2215", "Binder use-after-free", "HIGH", "2019-11-05", listOf("pegasus"),
                        "2021-11-03"),
                    CveEvidence("CVE-2024-0001", "Some other flaw", "CRITICAL", "2024-12-05", emptyList(),
                        "2024-12-10"),
                ),
                targetPatchLevel = "2024-12-05", campaignCount = 1,
            ),
            cve.evidence,
        )
        assertTrue(cve.remediation.isNotEmpty())
        val pegasus = findings.single { it.ruleId == "androdr-048" }
        assertEquals("2 CVEs linked to Pegasus", pegasus.title)
    }

    @Test
    fun `a round trip through the store evaluates to the same findings and evidence`() = runBlocking {
        val engine = engine(bundledRules())
        val groups = listOf(
            Triple(TelemetrySource.LIVE_SCAN, liveServices(), 1L),
            Triple(TelemetrySource.INTRUSION_LOG_IMPORT, mapOf(
                LiveRecordBuilders.DNS_MONITOR to intrusionRecords().getValue("importedDns"),
                IntrusionLogRecordBuilders.NETWORK_MONITOR to intrusionRecords().getValue("network"),
                IntrusionLogRecordBuilders.SECURITY_LOG to intrusionRecords().getValue("securityLog"),
            ), 2L),
            Triple(TelemetrySource.BUGREPORT_IMPORT, bugReportServices(), 3L),
        )
        var cveChecked = false
        for ((source, byService, scanId) in groups) {
            f.scan(scanId)
            byService.forEach { (service, records) ->
                records.chunked(ChunkedScanWriter.CHUNK_SIZE).forEachIndexed { i, chunk ->
                    f.persist(scanId, service, chunk, source = source, capturedAt = CAPTURED,
                        firstOrdinal = i * ChunkedScanWriter.CHUNK_SIZE)
                }
            }
            f.setState(scanId, ScanState.COMPLETE)
            for ((service, records) in byService) {
                val decoded = mutableListOf<StoreRecord>()
                f.reader.forEach(scanId, service) { decoded += StoreRecord(checkNotNull(it.fields)) }
                assertEquals("$service: every record is stored", records.size, decoded.size)
                assertEquals("$service: stored fields equal the live fields",
                    records.map { it.fields }, decoded.map { it.fields })
                val live: List<Finding> = engine.evaluateRecords(service, records, 0)
                assertEquals("$service: same findings after the store", live,
                    engine.evaluateRecords(service, decoded, 0))
                if (service == LiveRecordBuilders.DEVICE_AUDITOR) {
                    assertTrue("the CVE rule fires on the stored record",
                        live.any { it.ruleId == "androdr-047" && it.evidence is Evidence.CveList })
                    cveChecked = true
                }
            }
        }
        assertTrue(cveChecked)
    }

    private fun liveServices(): Map<String, List<StoreRecord>> {
        val l = liveRecords()
        return mapOf(
            LiveRecordBuilders.APP_SCANNER to l.getValue("apps"),
            LiveRecordBuilders.DEVICE_AUDITOR to l.getValue("device"),
            LiveRecordBuilders.PROCESS_MONITOR to l.getValue("processes"),
            LiveRecordBuilders.FILE_SCANNER to l.getValue("files"),
            LiveRecordBuilders.ACCESSIBILITY_AUDIT to l.getValue("accessibility"),
            LiveRecordBuilders.RECEIVER_AUDIT to l.getValue("receivers"),
            LiveRecordBuilders.APPOPS_AUDIT to l.getValue("appOps"),
            LiveRecordBuilders.USAGE_STATS to l.getValue("usage"),
            LiveRecordBuilders.DNS_MONITOR to l.getValue("dns"),
        )
    }

    private fun bugReportServices(): Map<String, List<StoreRecord>> {
        val b = bugReportRecords()
        return genericModuleRecords() + mapOf(
            BugReportRecordBuilders.TOMBSTONE_PARSER to b.getValue("tombstones"),
            BugReportRecordBuilders.WAKELOCK_PARSER to b.getValue("wakelocks"),
            BugReportRecordBuilders.BATTERY_DAILY to b.getValue("batteryDaily"),
            BugReportRecordBuilders.PACKAGE_INSTALL_HISTORY to b.getValue("packageInstallHistory"),
            BugReportRecordBuilders.PLATFORM_COMPAT to b.getValue("platformCompat"),
            BugReportRecordBuilders.DB_INFO to b.getValue("databasePathObservations"),
            BugReportRecordBuilders.SYSTEM_PROPERTY to b.getValue("systemProperties"),
        )
    }

    private fun engine(rules: List<SigmaRule>) = SigmaRuleEngine(mockk(relaxed = true)).apply {
        setRemoteRules(rules)
        setEvidenceProviders(ScanOrchestrator.buildEvidenceProviders(rules) { _, _ -> null })
    }

    private fun bundledRules(): List<SigmaRule> =
        listOf(File("app/src/main/res/raw"), File("src/main/res/raw")).first { it.isDirectory }
            .listFiles { file ->
                file.name.startsWith("sigma_androdr_") && !file.name.startsWith("sigma_androdr_corr_")
            }!!
            .sortedBy { it.name }
            .mapNotNull { SigmaRuleParser.parse(it.readText()) }

    private companion object {
        const val CAPTURED = 1_787_400_400_000L
    }
}
