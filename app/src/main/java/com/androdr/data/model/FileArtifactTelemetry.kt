package com.androdr.data.model

data class FileArtifactTelemetry(
    val filePath: String,
    val fileExists: Boolean,
    val fileSize: Long?,
    val fileModified: Long?,
    val source: TelemetrySource,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "file_path" to filePath,
        "file_exists" to fileExists,
        "file_size" to fileSize,
        "file_modified" to fileModified
    )
}
