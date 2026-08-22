package com.androdr.data.model

data class NetworkTelemetry(
    val destinationIp: String,
    val destinationPort: Int,
    /** Null when the source does not record it (Intrusion Logging imports). */
    val protocol: String?,
    val appUid: Int,
    val appName: String?,
    val timestamp: Long,
    val source: TelemetrySource,
    val capturedAt: Long
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "destination_ip" to destinationIp,
        "destination_port" to destinationPort,
        "protocol" to protocol,
        "app_uid" to appUid,
        "app_name" to appName,
        "timestamp" to timestamp,
        "source" to source.name,
        "captured_at" to capturedAt
    )
}
