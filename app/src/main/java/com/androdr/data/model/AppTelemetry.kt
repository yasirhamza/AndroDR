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
    // Security-relevant permissions, short-named (e.g. "CAMERA", "SYSTEM_ALERT_WINDOW"):
    // the surveillance set plus the curated high-risk set (see AppScanner). Rules
    // match individual tokens via `permissions|contains`. NOT the full requested list.
    // FROZEN compat surface: the fleet's shipped rules key on it; new rules should
    // key on requestedPermissions instead.
    val permissions: List<String>,
    // EVERY permission the app requests, verbatim fully-qualified names, zero
    // curation (emitter-emits-all-facts). Rules must match it with exact
    // element-wise equals, never `|contains`: android.permission.NFC is a
    // substring of android.permission.NFC_TRANSACTION_EVENT, so substring
    // matching false-positives. FLEET SAFETY — positive references only: on
    // builds that predate this field a matcher on it evaluates false (there is
    // NO unknown-field skip floor), which no-ops positive selections but
    // INVERTS under `not` in the condition, over-firing on the old fleet.
    // Never use this field in a negated filter until the fleet floor covers
    // the emitter; PermissionLiteralCrossCheckTest enforces this.
    val requestedPermissions: List<String> = emptyList(),
    // Count of surveillance perms ONLY (not high-risk perms) — see AppScanner.
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
    // NEW (#168):
    val embeddedComponentClasses: List<String> = emptyList(),
    val embeddedNativeLibs: List<String> = emptyList(),
    // WebAPK web scope from shell-manifest meta-data (#299); null for every
    // non-WebAPK app. ATTACKER-CONTROLLED (any app may adopt the prefix and
    // declare the key) — capped/sanitised in AppScanner before it lands here.
    val webapkScope: String? = null,
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
        "requested_permissions" to requestedPermissions,
        "surveillance_permission_count" to surveillancePermissionCount,
        "has_accessibility_service" to hasAccessibilityService,
        "has_device_admin" to hasDeviceAdmin,
        "known_app_category" to knownAppCategory,
        "service_permissions" to servicePermissions,
        "receiver_permissions" to receiverPermissions,
        "has_launcher_activity" to hasLauncherActivity,
        "first_install_time" to firstInstallTime,
        "last_update_time" to lastUpdateTime,
        // NEW (#168):
        "embedded_component_class" to embeddedComponentClasses,
        "embedded_native_lib" to embeddedNativeLibs,
        // NEW (#299):
        "webapk_scope" to webapkScope
    )
}
