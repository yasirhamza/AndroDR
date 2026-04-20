package com.androdr.data.model

data class AppTelemetry(
    val packageName: String,
    val appName: String,
    val certHash: String?,
    // SHA-1 of the same signing-cert bytes used for certHash (SHA-256). Required to
    // match community feeds (stalkerware-indicators, MVT) that index cert IOCs by
    // SHA-1 — the Android ecosystem convention (apksigner --print-certs emits SHA-1
    // by default).
    val certHashSha1: String?,
    val apkHash: String?,
    val isSystemApp: Boolean,
    val fromTrustedStore: Boolean,
    val installer: String?,
    val isSideloaded: Boolean,
    val isKnownOemApp: Boolean,
    val permissions: List<String>,
    val surveillancePermissionCount: Int,
    val hasAccessibilityService: Boolean,
    val hasDeviceAdmin: Boolean,
    val knownAppCategory: String?,
    // Raw component lists — enable manifest-based detections as pure SIGMA rule updates
    val servicePermissions: List<String> = emptyList(),
    val receiverPermissions: List<String> = emptyList(),
    val hasLauncherActivity: Boolean = true,
    /**
     * Epoch ms of first install. `0L` means unknown / not populated;
     * consumers MUST treat as missing, not as the actual epoch.
     */
    val firstInstallTime: Long = 0L,
    /**
     * Epoch ms of last update. `0L` means unknown / not populated;
     * consumers MUST treat as missing, not as the actual epoch.
     */
    val lastUpdateTime: Long = 0L,
    val source: TelemetrySource,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "package_name" to packageName,
        "app_name" to appName,
        "cert_hash" to certHash,
        "cert_hash_sha1" to certHashSha1,
        "apk_hash" to apkHash,
        "is_system_app" to isSystemApp,
        "from_trusted_store" to fromTrustedStore,
        "installer" to installer,
        "is_sideloaded" to isSideloaded,
        "is_known_oem_app" to isKnownOemApp,
        "permissions" to permissions,
        "surveillance_permission_count" to surveillancePermissionCount,
        "has_accessibility_service" to hasAccessibilityService,
        "has_device_admin" to hasDeviceAdmin,
        "known_app_category" to knownAppCategory,
        "service_permissions" to servicePermissions,
        "receiver_permissions" to receiverPermissions,
        "has_launcher_activity" to hasLauncherActivity,
        "first_install_time" to firstInstallTime,
        "last_update_time" to lastUpdateTime
    )
}
