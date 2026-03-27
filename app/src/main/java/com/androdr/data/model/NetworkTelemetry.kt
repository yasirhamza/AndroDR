package com.androdr.data.model

data class NetworkTelemetry(
    val destinationIp: String,
    val destinationPort: Int,
    val protocol: String,
    val appUid: Int,
    val appName: String?,
    val timestamp: Long
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "destination_ip" to destinationIp,
        "destination_port" to destinationPort,
        "protocol" to protocol,
        "app_uid" to appUid,
        "app_name" to appName,
        "timestamp" to timestamp
    )
}
