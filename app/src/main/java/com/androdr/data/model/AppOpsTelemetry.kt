package com.androdr.data.model

data class AppOpsTelemetry(
    val packageName: String,
    val operation: String,
    val lastAccessTime: Long,
    val lastRejectTime: Long,
    val accessCount: Int,
    val isSystemApp: Boolean
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "package_name" to packageName,
        "operation" to operation,
        "last_access_time" to lastAccessTime,
        "last_reject_time" to lastRejectTime,
        "access_count" to accessCount,
        "is_system_app" to isSystemApp
    )
}
