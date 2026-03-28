package com.androdr.data.model

data class ReceiverTelemetry(
    val packageName: String,
    val intentAction: String,
    val componentName: String,
    val isSystemApp: Boolean
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "package_name" to packageName,
        "intent_action" to intentAction,
        "component_name" to componentName,
        "is_system_app" to isSystemApp
    )
}
