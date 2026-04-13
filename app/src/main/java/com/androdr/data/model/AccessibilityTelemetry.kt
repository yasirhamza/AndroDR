package com.androdr.data.model

data class AccessibilityTelemetry(
    val packageName: String,
    val serviceName: String,
    val isSystemApp: Boolean,
    val isEnabled: Boolean,
    val source: TelemetrySource,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "package_name" to packageName,
        "service_name" to serviceName,
        "is_system_app" to isSystemApp,
        "is_enabled" to isEnabled
    )
}
