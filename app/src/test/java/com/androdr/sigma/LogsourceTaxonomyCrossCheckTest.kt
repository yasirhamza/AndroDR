package com.androdr.sigma

import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.BatteryDailyEvent
import com.androdr.data.model.DatabasePathObservation
import com.androdr.data.model.DeviceTelemetry
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.PackageHistoryEventType
import com.androdr.data.model.PackageInstallHistoryEntry
import com.androdr.data.model.PlatformCompatChange
import com.androdr.data.model.ProcessTelemetry
import com.androdr.data.model.ReceiverTelemetry
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TombstoneEvent
import com.androdr.data.model.WakelockAcquisition
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time cross-check: validates that logsource-taxonomy.yml field lists
 * match the actual toFieldMap() output for every service.
 *
 * Must be in com.androdr.sigma package for internal extension function visibility.
 */
class LogsourceTaxonomyCrossCheckTest {

    private fun taxonomyFile(): File? {
        val candidates = listOf(
            File("third-party/android-sigma-rules/validation/logsource-taxonomy.yml"),
            File("../third-party/android-sigma-rules/validation/logsource-taxonomy.yml"),
            File("/home/yasir/AndroDR/third-party/android-sigma-rules/validation/logsource-taxonomy.yml"),
        )
        return candidates.firstOrNull { it.isFile }
    }

    @Suppress("UNCHECKED_CAST")
    private fun loadTaxonomy(): Map<String, Map<String, Any?>> {
        val file = taxonomyFile()!!
        val yaml = Load(LoadSettings.builder().build())
        val root = yaml.loadFromString(file.readText()) as Map<String, Any?>
        return root["services"] as Map<String, Map<String, Any?>>
    }

    private fun taxonomyFieldNames(serviceEntry: Map<String, Any?>): Set<String> {
        @Suppress("UNCHECKED_CAST")
        val fields = serviceEntry["fields"] as? Map<String, Any?> ?: emptyMap()
        return fields.keys
    }

    /**
     * Build the map of service name → actual toFieldMap() keys from Kotlin code.
     * Member functions are called on dummy instances; extension functions are
     * called via imports from com.androdr.sigma (this package).
     */
    private fun actualFieldMaps(): Map<String, Set<String>> =
        memberFunctionFieldMaps() + extensionFunctionFieldMaps()

    /** Services whose toFieldMap() is a member function on the data class. */
    private fun memberFunctionFieldMaps(): Map<String, Set<String>> = mapOf(
        "app_scanner" to AppTelemetry(
            packageName = "x", appName = "x", certHash = null, apkHash = null,
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

        "dns_monitor" to DnsEvent(
            timestamp = 0L, domain = "x", appUid = 0, appName = null,
            isBlocked = false, reason = null,
        ).toFieldMap().keys,

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
            destinationIp = "x", destinationPort = 0, protocol = "TCP",
            appUid = 0, appName = null, timestamp = 0L,
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
            description = "x", source = TelemetrySource.BUGREPORT_IMPORT,
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
            observationTimestamp = 0L, source = TelemetrySource.BUGREPORT_IMPORT,
            capturedAt = 0L,
        ).toFieldMap().keys,
    )

    @Test
    fun `taxonomy file is reachable from submodule`() {
        val file = taxonomyFile()
        assertTrue(
            "logsource-taxonomy.yml not found. Run: git submodule update --init",
            file != null && file.isFile,
        )
    }

    @Test
    fun `taxonomy field names match toFieldMap output for every service`() {
        val file = taxonomyFile()
        assumeTrue(
            "Skipping: logsource-taxonomy.yml not found (submodule not initialized).",
            file != null && file.isFile,
        )

        val taxonomy = loadTaxonomy()
        val actual = actualFieldMaps()
        val failures = mutableListOf<String>()

        // Check every service in actual has a taxonomy entry
        for ((service, actualKeys) in actual) {
            val entry = taxonomy[service]
            if (entry == null) {
                failures += "$service: missing from taxonomy YAML"
                continue
            }
            val taxonomyKeys = taxonomyFieldNames(entry)
            val extraInKotlin = actualKeys - taxonomyKeys
            val extraInTaxonomy = taxonomyKeys - actualKeys
            if (extraInKotlin.isNotEmpty()) {
                failures += "$service: fields in Kotlin toFieldMap() but missing from taxonomy: $extraInKotlin"
            }
            if (extraInTaxonomy.isNotEmpty()) {
                failures += "$service: fields in taxonomy but missing from Kotlin toFieldMap(): $extraInTaxonomy"
            }
        }

        // Check for taxonomy services not covered by actual
        val untested = taxonomy.keys - actual.keys
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

    @Test
    fun `taxonomy service count matches expected`() {
        val file = taxonomyFile()
        assumeTrue(
            "Skipping: logsource-taxonomy.yml not found.",
            file != null && file.isFile,
        )

        val taxonomy = loadTaxonomy()
        val actual = actualFieldMaps()
        assertEquals(
            "Taxonomy service count must match Kotlin toFieldMap() count",
            actual.size,
            taxonomy.size,
        )
    }
}
