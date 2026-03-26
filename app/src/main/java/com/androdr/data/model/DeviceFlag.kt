@file:Suppress("MaxLineLength") // DeviceFlag description strings are human-readable security
// explanations; wrapping them would make them harder to read and search in the source.

package com.androdr.data.model

import kotlinx.serialization.Serializable

enum class Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    INFO
}

@Serializable
data class DeviceFlag(
    val id: String,
    val title: String,
    val description: String,
    val severity: Severity,
    val isTriggered: Boolean
) {
    companion object {

        fun adbEnabled(isTriggered: Boolean) = DeviceFlag(
            id = "adb_enabled",
            title = "USB Debugging",
            description = "ADB (Android Debug Bridge) is currently enabled. This allows a connected computer to execute arbitrary commands on the device.",
            severity = Severity.HIGH,
            isTriggered = isTriggered
        )

        fun devOptionsEnabled(isTriggered: Boolean) = DeviceFlag(
            id = "dev_options_enabled",
            title = "Developer Options",
            description = "Developer Options are turned on. This exposes advanced settings that can weaken device security.",
            severity = Severity.MEDIUM,
            isTriggered = isTriggered
        )

        fun unknownSources(isTriggered: Boolean) = DeviceFlag(
            id = "unknown_sources",
            title = "Unknown Sources Installation",
            description = "One or more apps are permitted to install APKs from outside the Play Store, increasing the risk of sideloaded malware.",
            severity = Severity.HIGH,
            isTriggered = isTriggered
        )

        fun noScreenLock(isTriggered: Boolean) = DeviceFlag(
            id = "no_screen_lock",
            title = "Screen Lock",
            description = "The device has no PIN, password, pattern, or biometric lock configured, leaving it fully accessible if lost or stolen.",
            severity = Severity.CRITICAL,
            isTriggered = isTriggered
        )

        fun stalePatchLevel(isTriggered: Boolean) = DeviceFlag(
            id = "stale_patch_level",
            title = "Security Patch Level",
            description = "The device's security patch level is more than 90 days old and may be missing critical vulnerability fixes.",
            severity = Severity.HIGH,
            isTriggered = isTriggered
        )

        fun bootloaderUnlocked(isTriggered: Boolean) = DeviceFlag(
            id = "bootloader_unlocked",
            title = "Bootloader",
            description = "The bootloader is unlocked, which disables Verified Boot and allows unsigned or modified system images to run.",
            severity = Severity.CRITICAL,
            isTriggered = isTriggered
        )

        fun wifiAdbEnabled(isTriggered: Boolean) = DeviceFlag(
            id = "wifi_adb_enabled",
            title = "Wireless ADB",
            description = "ADB over Wi-Fi is active. Any device on the same network may be able to connect and issue debug commands.",
            severity = Severity.HIGH,
            isTriggered = isTriggered
        )
    }
}
