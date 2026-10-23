package com.androdr.data.model

import com.androdr.sigma.toFieldMap
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Modifier

/**
 * Gate E2: a field map carries every fact its data class holds (spec §4.1).
 *
 * Records are stored as their `toFieldMap()` projection, so a constructor
 * property the map drops is a fact lost at write time. Each class's
 * constructor properties (camelCase -> snake_case) must appear as map keys,
 * unless [ALLOWED] says why not.
 */
class FieldMapCompletenessTest {

    private val live = TelemetrySource.LIVE_SCAN
    private val imported = TelemetrySource.BUGREPORT_IMPORT

    private val dnsEvent = DnsEvent(
        timestamp = 1L, domain = "x", appUid = 0, appName = null, isBlocked = false, reason = null,
    )

    /** One sample per telemetry class, paired with its field map. */
    private fun samples(): List<Pair<Any, Map<String, Any?>>> = liveSamples() + importedSamples()

    private fun liveSamples(): List<Pair<Any, Map<String, Any?>>> = listOf(
        AppTelemetry(
            packageName = "x", appName = "x", certHash = null, certHashSha1 = null, apkHash = null,
            isSystemApp = false, fromTrustedStore = false, installer = null, isSideloaded = false,
            isKnownOemApp = false, permissions = emptyList(), surveillancePermissionCount = 0,
            hasAccessibilityService = false, hasDeviceAdmin = false, knownAppCategory = null, source = live,
        ).let { it to it.toFieldMap() },
        DeviceTelemetry(checkId = "x", isTriggered = false, source = live).let { it to it.toFieldMap() },
        dnsEvent.let { it to it.toFieldMap() },
        ImportedDnsEvent(dnsEvent, listOf("1.2.3.4")).let { it to it.toFieldMap() },
        ProcessTelemetry(
            processName = "x", processUid = 0, packageName = null, isForeground = false, source = live,
        ).let { it to it.toFieldMap() },
        FileArtifactTelemetry(
            filePath = "x", fileExists = false, fileSize = null, fileModified = null, source = live,
        ).let { it to it.toFieldMap() },
        ReceiverTelemetry(
            packageName = "x", intentAction = "x", componentName = "x", isSystemApp = false, source = live,
        ).let { it to it.toFieldMap() },
        AccessibilityTelemetry(
            packageName = "x", serviceName = "x", isSystemApp = false, isEnabled = false, source = live,
        ).let { it to it.toFieldMap() },
        AppOpsTelemetry(
            packageName = "x", operation = "x", lastAccessTime = 0L, lastRejectTime = 0L,
            accessCount = 0, isSystemApp = false, source = live,
        ).let { it to it.toFieldMap() },
        NetworkTelemetry(
            destinationIp = "x", destinationPort = 0, protocol = null, appUid = 0, appName = null,
            timestamp = 0L, source = live, capturedAt = 0L,
        ).let { it to it.toFieldMap() },
        UsageEvent(
            timestamp = 1L, packageName = "x", appName = "x", eventType = "app_foreground",
            source = live, capturedAt = 0L,
        ).let { it to it.toFieldMap() },
    )

    private fun importedSamples(): List<Pair<Any, Map<String, Any?>>> = listOf(
        TombstoneEvent(
            processName = "x", packageName = null, signalNumber = null, abortMessage = null,
            crashTimestamp = 0L, source = imported, capturedAt = 0L,
        ).let { it to it.toFieldMap() },
        WakelockAcquisition(
            packageName = "x", wakelockTag = "x", acquiredAt = 0L, durationMillis = null,
            source = imported, capturedAt = 0L,
        ).let { it to it.toFieldMap() },
        BatteryDailyEvent(
            dayIndex = 0, eventType = "x", packageName = null, description = "x",
            source = imported, capturedAt = 0L,
        ).let { it to it.toFieldMap() },
        PackageInstallHistoryEntry(
            packageName = "x", eventType = PackageHistoryEventType.INSTALL, timestamp = 0L,
            versionCode = null, source = imported, capturedAt = 0L,
        ).let { it to it.toFieldMap() },
        PlatformCompatChange(
            changeId = "x", packageName = "x", enabled = false, source = imported, capturedAt = 0L,
        ).let { it to it.toFieldMap() },
        DatabasePathObservation(
            filePath = "x", processName = null, packageName = null, observationTimestamp = 0L,
            source = imported, capturedAt = 0L,
        ).let { it to it.toFieldMap() },
        SecurityLogEvent(
            timestamp = 0L, tag = 0, tagName = "x", securityData = emptyList(),
            source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
        ).let { it to it.toFieldMap() },
        SystemPropertySnapshot(key = "x", value = "x", source = imported, capturedAt = 0L)
            .let { it to it.toFieldMap() },
    )

    private fun constructorProperties(instance: Any): List<String> =
        instance.javaClass.declaredFields
            .filter { !Modifier.isStatic(it.modifiers) && !it.isSynthetic }
            .map { it.name }

    private fun snakeCase(name: String): String =
        name.replace(Regex("([a-z0-9])([A-Z])"), "$1_$2").lowercase()

    @Test
    fun `every constructor property reaches the field map`() {
        val failures = mutableListOf<String>()
        for ((instance, fieldMap) in samples()) {
            val cls = instance.javaClass.simpleName
            for (property in constructorProperties(instance)) {
                val qualified = "$cls.$property"
                if (qualified in ALLOWED) continue
                if (snakeCase(property) !in fieldMap.keys) {
                    failures += "$qualified -> \"${snakeCase(property)}\" missing from toFieldMap()"
                }
            }
        }
        assertTrue(
            "Field maps drop facts their class holds:\n" + failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }

    @Test
    fun `allow-list entries name real properties`() {
        val known = samples().flatMap { (instance, _) ->
            constructorProperties(instance).map { "${instance.javaClass.simpleName}.$it" }
        }.toSet()
        val stale = ALLOWED.keys - known
        assertTrue("Stale allow-list entries (property gone): $stale", stale.isEmpty())
    }

    private companion object {
        /**
         * Properties deliberately absent from the snake_case key, and why.
         * Keep each entry justified; a new gap needs a reason here or a key.
         */
        val ALLOWED = mapOf(
            // Room primary key, assigned on insert; not an observed fact.
            "DnsEvent.id" to "row id",
            // Published under the taxonomy key `source_package`.
            "DnsEvent.appName" to "source_package",
            // Flattened: ImportedDnsEvent's map is event.toFieldMap() + resolved_ips.
            "ImportedDnsEvent.event" to "flattened",
            // Published under the taxonomy keys embedded_component_class / embedded_native_lib.
            "AppTelemetry.embeddedComponentClasses" to "embedded_component_class",
            "AppTelemetry.embeddedNativeLibs" to "embedded_native_lib",
            // Live-scan provenance: always LIVE_SCAN for these classes, so the
            // observation's own source carries it (spec §4.1 envelope keys).
            "AppTelemetry.source" to "envelope",
            "DeviceTelemetry.source" to "envelope",
            "ProcessTelemetry.source" to "envelope",
            "FileArtifactTelemetry.source" to "envelope",
            "ReceiverTelemetry.source" to "envelope",
            "AccessibilityTelemetry.source" to "envelope",
            "AppOpsTelemetry.source" to "envelope",
        )
    }
}
