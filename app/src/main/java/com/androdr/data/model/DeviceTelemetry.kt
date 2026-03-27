package com.androdr.data.model

import com.androdr.data.model.CveEntity

data class DeviceTelemetry(
    val checkId: String,
    val isTriggered: Boolean,
    val adbEnabled: Boolean = false,
    val devOptionsEnabled: Boolean = false,
    val unknownSourcesEnabled: Boolean = false,
    val screenLockEnabled: Boolean = true,
    val patchLevel: String = "",
    val patchAgeDays: Int = 0,
    val bootloaderUnlocked: Boolean = false,
    val wifiAdbEnabled: Boolean = false,
    val unpatchedCveCount: Int = 0,
    val unpatchedCves: List<Any> = emptyList()
) {
    fun toFieldMap(): Map<String, Any?> {
        // Build comma-joined CVE ID string for campaign rule matching via |contains
        val cveIdString = unpatchedCves
            .filterIsInstance<CveEntity>()
            .joinToString(",") { it.cveId }

        return mapOf(
            "check_id" to checkId,
            "is_triggered" to isTriggered,
            "adb_enabled" to adbEnabled,
            "dev_options_enabled" to devOptionsEnabled,
            "unknown_sources_enabled" to unknownSourcesEnabled,
            "screen_lock_enabled" to screenLockEnabled,
            "patch_level" to patchLevel,
            "patch_age_days" to patchAgeDays,
            "bootloader_unlocked" to bootloaderUnlocked,
            "wifi_adb_enabled" to wifiAdbEnabled,
            "unpatched_cve_count" to unpatchedCveCount,
            "unpatched_cves" to unpatchedCves,
            "unpatched_cve_id" to cveIdString
        )
    }
}
