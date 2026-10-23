package com.androdr.sigma

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
import com.androdr.data.model.SystemPropertySnapshot
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TombstoneEvent
import com.androdr.data.model.UsageEvent
import com.androdr.data.model.WakelockAcquisition
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import com.androdr.scanner.bugreport.ActivityModule
import com.androdr.scanner.bugreport.AdbKeysModule
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Build-time cross-check: validates that logsource-taxonomy.yml field lists
 * match the actual toFieldMap() output for every service, in both directions.
 *
 * Must be in com.androdr.sigma package for internal extension function visibility.
 */
class LogsourceTaxonomyCrossCheckTest {

    private fun taxonomy(): Map<String, TestRuleRepo.TaxonomyService>? = TestRuleRepo.loadTaxonomy()

    /**
     * Build the map of service name → actual toFieldMap() keys from Kotlin code.
     * Member functions are called on dummy instances; extension functions are
     * called via imports from com.androdr.sigma (this package); engine-matched
     * services have no toFieldMap() and are built from the engine's own
     * constants; module-record services come from running the module.
     */
    private fun actualFieldMaps(): Map<String, Set<String>> =
        memberFunctionFieldMaps() + extensionFunctionFieldMaps() + engineMatchedFieldMaps() +
            moduleRecordFieldMaps()

    /**
     * Services with NO toFieldMap(): the engine matches literal field names
     * directly. `timeline` atoms are bound by SigmaRuleEngine.computeAtomBindings,
     * which consults exactly [SigmaRuleEngine.ATOM_BINDING_FIELD] — building the
     * entry from that production constant keeps this a genuine code↔taxonomy
     * cross-check rather than a hand-mirrored literal that drifts silently.
     */
    private fun engineMatchedFieldMaps(): Map<String, Set<String>> = mapOf(
        "timeline" to setOf(SigmaRuleEngine.ATOM_BINDING_FIELD),
    )

    /**
     * Emitter-only services with no data class (`field_map: none`): the
     * bug-report module builds a literal map, so the keys come from running the
     * module on a minimal section.
     */
    private fun moduleRecordFieldMaps(): Map<String, Set<String>> = runBlocking {
        val resolver = mockk<IndicatorResolver>()
        every { resolver.isKnownBadPackage(any()) } returns null
        val adb = AdbKeysModule().analyze(
            "USB debugging: enabled\nTrusted keys:\n  QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFh user@host\n",
            resolver, DeviceIdentity.UNKNOWN,
        )
        val activity = ActivityModule(mockk(relaxed = true)).analyze(
            """
                Activity Resolver Table:
                  Schemes:
                      http:
                        12345 com.example.browser/.MainActivity filter abcdef
                          Action: "android.intent.action.VIEW"
            """.trimIndent(),
            resolver, DeviceIdentity.UNKNOWN,
        )
        mapOf(
            "adb_audit" to adb.telemetry.single().keys,
            "activity_audit" to activity.telemetry.single().keys,
        )
    }

    private val dnsEvent = DnsEvent(
        timestamp = 0L, domain = "x", appUid = 0, appName = null,
        isBlocked = false, reason = null,
    )

    /** Services whose toFieldMap() is a member function on the data class. */
    private fun memberFunctionFieldMaps(): Map<String, Set<String>> = mapOf(
        "app_scanner" to AppTelemetry(
            packageName = "x", appName = "x", certHash = null, certHashSha1 = null, apkHash = null,
            isSystemApp = false, fromTrustedStore = false, installer = null,
            isSideloaded = false, isKnownOemApp = false, permissions = emptyList(),
            surveillancePermissionCount = 0, hasAccessibilityService = false,
            hasDeviceAdmin = false, knownAppCategory = null,
            source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "device_auditor" to DeviceTelemetry(
            checkId = "x", isTriggered = false,
            source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        // Live and imported DNS share the service; the imported map is the
        // superset (it adds resolved_ips), and the live one must be a subset.
        "dns_monitor" to ImportedDnsEvent(dnsEvent, listOf("1.2.3.4")).toFieldMap().keys,

        "process_monitor" to ProcessTelemetry(
            processName = "x", processUid = 0, packageName = null,
            isForeground = false, source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "file_scanner" to FileArtifactTelemetry(
            filePath = "x", fileExists = false, fileSize = null,
            fileModified = null, source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "receiver_audit" to ReceiverTelemetry(
            packageName = "x", intentAction = "x", componentName = "x",
            isSystemApp = false, source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "accessibility_audit" to AccessibilityTelemetry(
            packageName = "x", serviceName = "x", isSystemApp = false,
            isEnabled = false, source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "appops_audit" to AppOpsTelemetry(
            packageName = "x", operation = "x", lastAccessTime = 0L,
            lastRejectTime = 0L, accessCount = 0, isSystemApp = false,
            source = TelemetrySource.LIVE_SCAN,
        ).toFieldMap().keys,

        "network_monitor" to NetworkTelemetry(
            destinationIp = "x", destinationPort = 0, protocol = null,
            appUid = 0, appName = null, timestamp = 0L,
            source = TelemetrySource.LIVE_SCAN, capturedAt = 0L,
        ).toFieldMap().keys,

        "usage_stats" to UsageEvent(
            timestamp = 0L, packageName = "x", appName = "x", eventType = "app_foreground",
            source = TelemetrySource.LIVE_SCAN, capturedAt = 0L,
        ).toFieldMap().keys,

        "system_property" to SystemPropertySnapshot(
            key = "x", value = "x", source = TelemetrySource.BUGREPORT_IMPORT, capturedAt = 0L,
        ).toFieldMap().keys,
    )

    /** Services whose toFieldMap() is an internal extension fn in com.androdr.sigma. */
    private fun extensionFunctionFieldMaps(): Map<String, Set<String>> = mapOf(
        "tombstone_parser" to TombstoneEvent(
            processName = "x", packageName = null, signalNumber = null,
            abortMessage = null, crashTimestamp = 0L,
            source = TelemetrySource.BUGREPORT_IMPORT, capturedAt = 0L,
        ).toFieldMap().keys,

        "wakelock_parser" to WakelockAcquisition(
            packageName = "x", wakelockTag = "x", acquiredAt = 0L,
            durationMillis = null, source = TelemetrySource.BUGREPORT_IMPORT,
            capturedAt = 0L,
        ).toFieldMap().keys,

        "battery_daily" to BatteryDailyEvent(
            dayIndex = 0, eventType = "x", packageName = null,
            description = "x", version = 0L, timestamp = 0L, timestampPrecision = "day",
            source = TelemetrySource.BUGREPORT_IMPORT,
            capturedAt = 0L,
        ).toFieldMap().keys,

        "package_install_history" to PackageInstallHistoryEntry(
            packageName = "x", eventType = PackageHistoryEventType.INSTALL,
            timestamp = 0L, versionCode = null,
            source = TelemetrySource.BUGREPORT_IMPORT, capturedAt = 0L,
        ).toFieldMap().keys,

        "platform_compat" to PlatformCompatChange(
            changeId = "x", packageName = "x", enabled = false,
            source = TelemetrySource.BUGREPORT_IMPORT, capturedAt = 0L,
        ).toFieldMap().keys,

        "db_info" to DatabasePathObservation(
            filePath = "x", processName = null, packageName = null,
            observationTimestamp = 0L, dbPath = "x", recentQueryCount = 0,
            source = TelemetrySource.BUGREPORT_IMPORT, capturedAt = 0L,
        ).toFieldMap().keys,

        "security_log" to SecurityLogEvent(
            timestamp = 0L, tag = 0, tagName = "x", securityData = emptyList(),
            source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
        ).toFieldMap().keys,
    )

    @Test
    fun `taxonomy file is reachable from submodule`() {
        assertTrue(
            "logsource-taxonomy.yml not found. Run: git submodule update --init",
            taxonomy() != null,
        )
    }

    @Test
    fun `live dns map is the imported map without resolved_ips`() {
        assertEquals(
            ImportedDnsEvent(dnsEvent, emptyList()).toFieldMap().keys - "resolved_ips",
            dnsEvent.toFieldMap().keys,
        )
    }

    @Test
    fun `taxonomy field names match toFieldMap output for every service`() {
        val taxonomy = taxonomy()
        assumeTrue("Skipping: logsource-taxonomy.yml not found (submodule not initialized).", taxonomy != null)

        val actual = actualFieldMaps()
        val failures = mutableListOf<String>()

        for ((service, actualKeys) in actual) {
            val entry = taxonomy!![service]
            if (entry == null) {
                failures += "$service: missing from taxonomy YAML"
                continue
            }
            val extraInKotlin = actualKeys - entry.fields
            // A field only some producers set (`optional: true`), or one whose
            // producer lands in a later task ([PENDING_PRODUCER]), may be absent
            // from this producer's map.
            val extraInTaxonomy = entry.fields - actualKeys - entry.optionalFields -
                PENDING_PRODUCER[service].orEmpty().keys
            if (extraInKotlin.isNotEmpty()) {
                failures += "$service: fields in Kotlin toFieldMap() but missing from taxonomy: $extraInKotlin"
            }
            if (extraInTaxonomy.isNotEmpty()) {
                failures += "$service: fields in taxonomy but missing from Kotlin toFieldMap(): $extraInTaxonomy"
            }
        }

        val untested = taxonomy!!.keys - actual.keys
        if (untested.isNotEmpty()) {
            failures += "Taxonomy services with no Kotlin cross-check: $untested"
        }

        if (failures.isNotEmpty()) {
            fail(
                "Taxonomy cross-check FAILED:\n" +
                    failures.joinToString("\n") { "  - $it" } + "\n\n" +
                    "If you added/removed a field in toFieldMap(), update " +
                    "logsource-taxonomy.yml in the android-sigma-rules submodule."
            )
        }
    }

    /**
     * A pending entry is temporary: once its producer emits the field it must
     * leave [PENDING_PRODUCER]. Until then neither old nor current binaries emit
     * it, so the taxonomy must flag it positive-only.
     */
    @Test
    fun `pending producer entries are still pending and positive-only`() {
        val taxonomy = taxonomy()
        assumeTrue("Skipping: logsource-taxonomy.yml not found.", taxonomy != null)
        val actual = actualFieldMaps()
        val failures = mutableListOf<String>()
        for ((service, fields) in PENDING_PRODUCER) {
            val entry = taxonomy!![service]
            for (field in fields.keys) {
                when {
                    field in actual[service].orEmpty() ->
                        failures += "$service.$field is now emitted: remove it from PENDING_PRODUCER"
                    entry == null || field !in entry.fields ->
                        failures += "$service.$field is not in the taxonomy"
                    field !in entry.positiveOnlyFields && field !in entry.optionalFields ->
                        failures += "$service.$field must be positive_only while no producer emits it"
                }
            }
        }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun `taxonomy service count matches expected`() {
        val taxonomy = taxonomy()
        assumeTrue("Skipping: logsource-taxonomy.yml not found.", taxonomy != null)
        assertEquals(
            "Taxonomy service count must match Kotlin toFieldMap() count",
            actualFieldMaps().size,
            taxonomy!!.size,
        )
    }

    private companion object {
        /**
         * Taxonomy fields declared ahead of their Kotlin producer (spec §4.2:
         * the taxonomy lands in Phase 0, before the typed bug-report records of
         * §5.3 exist). Service -> field -> the plan task whose typed record
         * emits it.
         */
        val PENDING_PRODUCER: Map<String, Map<String, String>> = emptyMap()
    }
}
