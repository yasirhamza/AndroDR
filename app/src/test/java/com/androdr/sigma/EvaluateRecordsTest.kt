package com.androdr.sigma

import android.content.Context
import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.BatteryDailyEvent
import com.androdr.data.model.DatabasePathObservation
import com.androdr.data.model.DeviceTelemetry
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.PackageHistoryEventType
import com.androdr.data.model.PackageInstallHistoryEntry
import com.androdr.data.model.PlatformCompatChange
import com.androdr.data.model.ProcessTelemetry
import com.androdr.data.model.ReceiverTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TombstoneEvent
import com.androdr.data.model.WakelockAcquisition
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import java.lang.reflect.Modifier

/**
 * E1, engine half: the typed `evaluate*` entry points and [SigmaRuleEngine.evaluateRecords]
 * evaluate the same maps, and every finding carries the ordinal of its record.
 */
class EvaluateRecordsTest {

    private lateinit var engine: SigmaRuleEngine

    /** A never-matching rule that reports safe state: one finding per evaluated record. */
    private fun perRecordRule(service: String) = SigmaRule(
        id = "test-$service", title = "per record", status = "production",
        description = "", product = "androdr", service = service, level = "low",
        category = RuleCategory.INCIDENT, tags = emptyList(),
        detection = SigmaDetection(
            selections = mapOf(
                "selection" to SigmaSelection(
                    fieldMatchers = listOf(
                        SigmaFieldMatcher("no_such_field", SigmaModifier.EQUALS, listOf("x"))
                    )
                )
            ),
            condition = "selection",
        ),
        falsepositives = emptyList(), remediation = emptyList(),
        display = SigmaDisplay(category = FindingCategory.DEVICE_POSTURE),
        reportSafeState = true,
    )

    @Before
    fun setUp() {
        engine = SigmaRuleEngine(mockk<Context>(relaxed = true))
        val rules = entryPoints.map { it.service }.distinct().map { perRecordRule(it) }
        for (field in listOf("bundledRules", "rules")) {
            SigmaRuleEngine::class.java.getDeclaredField(field).apply { isAccessible = true }
                .set(engine, rules)
        }
    }

    private fun file(path: String, accessible: Boolean = true) = FileArtifactTelemetry(
        filePath = path, fileExists = true, fileSize = 1L, fileModified = 2L,
        source = TelemetrySource.LIVE_SCAN, accessible = accessible,
    )

    private fun dns(domain: String, id: Long = 0) = DnsEvent(
        id = id, timestamp = 5L, domain = domain, appUid = 1, appName = "a", isBlocked = false, reason = null,
    )

    /**
     * One typed entry point, the logsource service it must evaluate under, spelled as a literal
     * (independent of the `*RecordBuilders` constants it is checking), and a call with two records.
     */
    private class EntryPoint(val name: String, val service: String, val call: SigmaRuleEngine.() -> List<Finding>)

    private val live = TelemetrySource.LIVE_SCAN
    private val br = TelemetrySource.BUGREPORT_IMPORT
    private val il = TelemetrySource.INTRUSION_LOG_IMPORT

    private val app = AppTelemetry(
        packageName = "com.example.a", appName = "A", certHash = "ab12", certHashSha1 = "cd34", apkHash = "ef56",
        isSystemApp = false, fromTrustedStore = false, installer = "com.android.shell", isSideloaded = true,
        isKnownOemApp = false, permissions = emptyList(), requestedPermissions = emptyList(),
        surveillancePermissionCount = 0, hasAccessibilityService = false, hasDeviceAdmin = false,
        hasBootReceiver = false, knownAppCategory = "USER_APP", servicePermissions = emptyList(),
        receiverPermissions = emptyList(), hasLauncherActivity = true, firstInstallTime = 1L, lastUpdateTime = 2L,
        source = live,
    )

    private val entryPoints = listOf(
        EntryPoint("evaluateApps", "app_scanner") { evaluateApps(listOf(app, app.copy(packageName = "b"))) },
        EntryPoint("evaluateDevice", "device_auditor") {
            evaluateDevice(List(2) { DeviceTelemetry("c$it", it == 1, source = live) })
        },
        EntryPoint("evaluateProcesses", "process_monitor") {
            evaluateProcesses(List(2) { ProcessTelemetry("p$it", 1, "a", true, live) })
        },
        EntryPoint("evaluateDns", "dns_monitor") { evaluateDns(listOf(dns("a.example"), dns("b.example"))) },
        EntryPoint("evaluateImportedDns", "dns_monitor") {
            evaluateImportedDns(List(2) { ImportedDnsEvent(dns("d$it.example"), listOf("1.2.3.4")) })
        },
        EntryPoint("evaluateFiles", "file_scanner") { evaluateFiles(listOf(file("/a"), file("/b"))) },
        EntryPoint("evaluateAccessibility", "accessibility_audit") {
            evaluateAccessibility(List(2) { AccessibilityTelemetry("a", "a/.S$it", false, true, live) })
        },
        EntryPoint("evaluateReceivers", "receiver_audit") {
            evaluateReceivers(List(2) { ReceiverTelemetry("a", "act$it", "a/.R", false, live) })
        },
        EntryPoint("evaluateAppOps", "appops_audit") {
            evaluateAppOps(List(2) { AppOpsTelemetry("a", "CAMERA$it", 1L, 0L, 1, false, live) })
        },
        EntryPoint("evaluateTombstones", "tombstone_parser") {
            evaluateTombstones(List(2) { TombstoneEvent("p$it", null, 6, "m", 9L, br, 10L) })
        },
        EntryPoint("evaluateWakelocks", "wakelock_parser") {
            evaluateWakelocks(List(2) { WakelockAcquisition("a", "tag$it", 1L, null, br, 10L) })
        },
        EntryPoint("evaluateBatteryDaily", "battery_daily") {
            evaluateBatteryDaily(List(2) { BatteryDailyEvent(it, "install", "a", "d", source = br, capturedAt = 10L) })
        },
        EntryPoint("evaluatePackageInstallHistory", "package_install_history") {
            evaluatePackageInstallHistory(List(2) {
                PackageInstallHistoryEntry("a", PackageHistoryEventType.INSTALL, it.toLong(), null, br, 10L)
            })
        },
        EntryPoint("evaluatePlatformCompat", "platform_compat") {
            evaluatePlatformCompat(List(2) { PlatformCompatChange("$it", "a", true, br, 10L) })
        },
        EntryPoint("evaluateDatabasePathObservations", "db_info") {
            evaluateDatabasePathObservations(
                List(2) { DatabasePathObservation("/d$it", null, "a", 1L, source = br, capturedAt = 10L) })
        },
        EntryPoint("evaluateNetwork", "network_monitor") {
            evaluateNetwork(List(2) { NetworkTelemetry("1.1.1.$it", 443, null, 1, "a", 1L, il, 10L) })
        },
        EntryPoint("evaluateSecurityLog", "security_log") {
            evaluateSecurityLog(List(2) { SecurityLogEvent(1L, it, "t", listOf("d"), il, 3L) })
        },
    )

    @Test
    fun `every typed entry point evaluates under its own service literal, with ordinals`() {
        val typed = SigmaRuleEngine::class.java.declaredMethods
            .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic && it.name.startsWith("evaluate") }
            .filter { it.parameterTypes.contentEquals(arrayOf(List::class.java)) }
            .map { it.name }.toSortedSet()
        assertEquals("every typed entry point is in the table", typed, entryPoints.map { it.name }.toSortedSet())
        for (e in entryPoints) {
            val findings = engine.(e.call)()
            assertEquals(e.name, listOf(e.service, e.service), findings.map { it.service })
            assertEquals(e.name, listOf(0, 1), findings.map { it.ordinal })
            assertEquals(e.name, listOf("test-${e.service}"), findings.map { it.ruleId }.distinct())
        }
    }

    @Test
    fun `the record builders declare each service literal once`() {
        val consts = listOf(LiveRecordBuilders::class.java, IntrusionLogRecordBuilders::class.java,
            BugReportRecordBuilders::class.java).flatMap { c ->
            c.declaredFields.filter { Modifier.isStatic(it.modifiers) && it.type == String::class.java }
                .map { "${c.simpleName}.${it.name}" to it.get(null) as String }
        }
        val dupes = consts.groupBy({ it.second }, { it.first }).filterValues { it.size > 1 }
        assertEquals("service literals declared more than once", emptyMap<String, List<String>>(), dupes)
    }

    @Test
    fun `live builders keep record order, fields and the DNS source key`() {
        val dnsRecords = LiveRecordBuilders.dns(listOf(dns("a.example", id = 7), dns("b.example", id = 8)))
        assertEquals(listOf("dns:7", "dns:8"), dnsRecords.map { it.sourceEventKey })
        assertEquals(
            mapOf("timestamp" to 5L, "domain" to "a.example", "app_uid" to 1, "source_package" to "a",
                "is_blocked" to false, "reason" to null),
            dnsRecords.first().fields,
        )
        assertEquals(listOf("a.example", "b.example"), dnsRecords.map { it.fields["domain"] })
        val files = LiveRecordBuilders.files(listOf(file("/a"), file("/b", accessible = false)))
        assertEquals(
            listOf(
                mapOf("file_path" to "/a", "file_exists" to true, "file_size" to 1L, "file_modified" to 2L,
                    "accessible" to true),
                mapOf("file_path" to "/b", "file_exists" to true, "file_size" to 1L, "file_modified" to 2L,
                    "accessible" to false),
            ),
            files.map { it.fields },
        )
        assertEquals(listOf(null, null), files.map { it.sourceEventKey })
    }

    @Test
    fun `bug report and intrusion log builders keep fields and pair source keys by index`() {
        val tomb = BugReportRecordBuilders.tombstones(
            listOf(TombstoneEvent("p", null, 6, "m", 9L, TelemetrySource.BUGREPORT_IMPORT, 10L)))
        assertEquals(
            mapOf("process_name" to "p", "package_name" to null, "signal_number" to 6, "abort_message" to "m",
                "crash_timestamp" to 9L, "source" to "BUGREPORT_IMPORT", "captured_at" to 10L),
            tomb.single().fields,
        )
        val generic = listOf(mapOf<String, Any?>("k" to "v"), mapOf<String, Any?>("k" to "w"))
        assertEquals(generic, BugReportRecordBuilders.generic(generic).map { it.fields })
        val imported = List(2) { ImportedDnsEvent(dns("d$it.example"), listOf("1.2.3.$it")) }
        val importedRecords = IntrusionLogRecordBuilders.importedDns(imported, listOf("k0", "k1"))
        assertEquals(listOf("k0", "k1"), importedRecords.map { it.sourceEventKey })
        assertEquals(
            mapOf("timestamp" to 5L, "domain" to "d0.example", "app_uid" to 1, "source_package" to "a",
                "resolved_ips" to listOf("1.2.3.0")),
            importedRecords.first().fields,
        )
        assertEquals(listOf(null, null), IntrusionLogRecordBuilders.importedDns(imported).map { it.sourceEventKey })
        val sec = IntrusionLogRecordBuilders.securityLog(
            listOf(SecurityLogEvent(1L, 2, "t", listOf("d"), TelemetrySource.INTRUSION_LOG_IMPORT, 3L)), listOf("s"))
        assertEquals(
            mapOf("timestamp" to 1L, "tag" to 2, "tag_name" to "t", "security_data" to listOf("d"),
                "source" to "INTRUSION_LOG_IMPORT", "captured_at" to 3L),
            sec.single().fields,
        )
        assertEquals("s", sec.single().sourceEventKey)
    }

    @Test
    fun `typed entry point gives the findings evaluateRecords gives`() {
        val events = listOf(dns("a.example"), dns("b.example"), dns("c.example"))
        val direct = engine.evaluateRecords("dns_monitor", LiveRecordBuilders.dns(events), 0)
        assertEquals(direct, engine.evaluateDns(events))
    }

    @Test
    fun `firstOrdinal offsets every finding`() {
        val events = listOf(dns("a.example"), dns("b.example"))
        val findings = engine.evaluateRecords("dns_monitor", LiveRecordBuilders.dns(events), 40)
        assertEquals(listOf(40, 41), findings.map { it.ordinal })
    }

    @Test
    fun `an inaccessible file at index 0 still consumes ordinal 0`() {
        val findings = engine.evaluateFiles(listOf(file("/hidden", accessible = false), file("/seen")))
        assertEquals(1, findings.size)
        assertEquals(1, findings.single().ordinal)
        assertEquals("file_scanner", findings.single().service)
    }

    @Test
    fun `evaluate include predicate skips a record but keeps its ordinal`() {
        val rule = perRecordRule("dns_monitor")
        val records = listOf(mapOf<String, Any?>("a" to 1), mapOf("a" to 2), mapOf("a" to 3))
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), records, "dns_monitor", firstOrdinal = 10, include = { it != 1 },
        )
        assertEquals(listOf(10, 12), findings.map { it.ordinal })
    }
}
