package com.androdr.data.model

data class ProcessTelemetry(
    val processName: String,
    val processUid: Int,
    val packageName: String?,
    val isForeground: Boolean,
    val source: TelemetrySource,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "process_name" to processName,
        "process_uid" to processUid,
        "package_name" to packageName,
        "is_foreground" to isForeground
    )
}
