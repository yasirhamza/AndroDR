package com.androdr.data.model

data class AppTelemetry(
    val packageName: String,
    val appName: String,
    val certHash: String?,
    val isSystemApp: Boolean,
    val fromTrustedStore: Boolean,
    val installer: String?,
    val isSideloaded: Boolean,
    val isKnownOemApp: Boolean,
    val permissions: List<String>,
    val surveillancePermissionCount: Int,
    val hasAccessibilityService: Boolean,
    val hasDeviceAdmin: Boolean,
    val knownAppCategory: String?
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "package_name" to packageName,
        "app_name" to appName,
        "cert_hash" to certHash,
        "is_system_app" to isSystemApp,
        "from_trusted_store" to fromTrustedStore,
        "installer" to installer,
        "is_sideloaded" to isSideloaded,
        "is_known_oem_app" to isKnownOemApp,
        "permissions" to permissions,
        "surveillance_permission_count" to surveillancePermissionCount,
        "has_accessibility_service" to hasAccessibilityService,
        "has_device_admin" to hasDeviceAdmin,
        "known_app_category" to knownAppCategory
    )
}
