package com.androdr.data.model


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
    val unpatchedCves: List<CveEntity> = emptyList(),
    val source: TelemetrySource,
) {
    fun toFieldMap(): Map<String, Any?> {
        // Build comma-joined CVE ID string for campaign rule matching via |contains
        val cveIdString = unpatchedCves.joinToString(",") { it.cveId }

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
            // Plain maps, never CveEntity: a field map holds only what CanonicalJson stores, so the
            // stored record reads back exactly as evaluated (ruling R21).
            "unpatched_cves" to unpatchedCves.map { it.toCveFieldMap() },
            "unpatched_cve_id" to cveIdString
        )
    }
}

/** Field-map keys of one entry of `unpatched_cves` (ruling R21); `CveEvidenceProvider` reads them. */
object CveFields {
    const val CVE_ID = "cve_id"
    const val DESCRIPTION = "description"
    const val SEVERITY = "severity"
    const val FIXED_IN_PATCH_LEVEL = "fixed_in_patch_level"
    const val CISA_DATE_ADDED = "cisa_date_added"
}

/** One `unpatched_cves` entry: a plain map of [CveFields] keys, nulls kept as null. */
fun CveEntity.toCveFieldMap(): Map<String, Any?> = mapOf(
    CveFields.CVE_ID to cveId,
    CveFields.DESCRIPTION to description,
    CveFields.SEVERITY to severity,
    CveFields.FIXED_IN_PATCH_LEVEL to fixedInPatchLevel,
    CveFields.CISA_DATE_ADDED to cisaDateAdded,
)
