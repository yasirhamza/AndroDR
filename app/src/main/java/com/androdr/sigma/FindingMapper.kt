// app/src/main/java/com/androdr/sigma/FindingMapper.kt
package com.androdr.sigma

import com.androdr.data.model.AppRisk
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.DeviceFlag
import com.androdr.data.model.DeviceTelemetry
import com.androdr.data.model.RiskLevel
import com.androdr.data.model.Severity

object FindingMapper {

    fun toAppRisks(
        telemetry: List<AppTelemetry>,
        findings: List<Finding>
    ): List<AppRisk> {
        val findingsByPackage = findings.groupBy {
            it.matchedRecord["package_name"]?.toString() ?: ""
        }

        return findingsByPackage.mapNotNull { (packageName, packageFindings) ->
            val app = telemetry.find { it.packageName == packageName } ?: return@mapNotNull null

            val reasons = packageFindings.map { it.title }

            val highestLevel = packageFindings
                .map { sigmaLevelToRiskLevel(it.level) }
                .maxByOrNull { it.score } ?: RiskLevel.LOW

            val isKnownMalware = packageFindings.any { it.level == "critical" &&
                it.ruleId.startsWith("androdr-00") }

            AppRisk(
                packageName = packageName,
                appName = app.appName,
                riskLevel = highestLevel,
                reasons = reasons,
                isKnownMalware = isKnownMalware,
                isSideloaded = app.isSideloaded,
                dangerousPermissions = app.permissions
            )
        }.sortedByDescending { it.riskLevel.score }
    }

    fun toDeviceFlags(
        telemetry: List<DeviceTelemetry>,
        findings: List<Finding>
    ): List<DeviceFlag> {
        val triggeredIds = findings.map {
            it.matchedRecord["check_id"]?.toString() ?: ""
        }.toSet()

        return telemetry.map { check ->
            val isTriggered = check.checkId in triggeredIds
            DeviceFlag(
                id = check.checkId,
                title = CHECK_TITLES[check.checkId] ?: check.checkId,
                description = CHECK_DESCRIPTIONS[check.checkId] ?: "",
                severity = CHECK_SEVERITIES[check.checkId] ?: Severity.MEDIUM,
                isTriggered = isTriggered
            )
        }
    }

    private fun sigmaLevelToRiskLevel(level: String): RiskLevel = when (level.lowercase()) {
        "critical" -> RiskLevel.CRITICAL
        "high" -> RiskLevel.HIGH
        "medium" -> RiskLevel.MEDIUM
        "low" -> RiskLevel.LOW
        else -> RiskLevel.MEDIUM
    }

    private val CHECK_TITLES = mapOf(
        "adb_enabled" to "USB Debugging",
        "dev_options_enabled" to "Developer Options",
        "unknown_sources" to "Unknown Sources Installation",
        "no_screen_lock" to "Screen Lock",
        "stale_patch_level" to "Security Patch Level",
        "bootloader_unlocked" to "Bootloader",
        "wifi_adb_enabled" to "Wireless ADB"
    )

    @Suppress("MaxLineLength")
    private val CHECK_DESCRIPTIONS = mapOf(
        "adb_enabled" to
            "ADB (Android Debug Bridge) is currently enabled. This allows a connected computer to execute arbitrary commands on the device.",
        "dev_options_enabled" to
            "Developer Options are turned on. This exposes advanced settings that can weaken device security.",
        "unknown_sources" to
            "One or more apps are permitted to install APKs from outside the Play Store, increasing the risk of sideloaded malware.",
        "no_screen_lock" to
            "The device has no PIN, password, pattern, or biometric lock configured, leaving it fully accessible if lost or stolen.",
        "stale_patch_level" to
            "The device's security patch level is more than 90 days old and may be missing critical vulnerability fixes.",
        "bootloader_unlocked" to
            "The bootloader is unlocked, which disables Verified Boot and allows unsigned or modified system images to run.",
        "wifi_adb_enabled" to
            "ADB over Wi-Fi is active. Any device on the same network may be able to connect and issue debug commands."
    )

    private val CHECK_SEVERITIES = mapOf(
        "adb_enabled" to Severity.HIGH,
        "dev_options_enabled" to Severity.MEDIUM,
        "unknown_sources" to Severity.HIGH,
        "no_screen_lock" to Severity.CRITICAL,
        "stale_patch_level" to Severity.HIGH,
        "bootloader_unlocked" to Severity.CRITICAL,
        "wifi_adb_enabled" to Severity.HIGH
    )
}
