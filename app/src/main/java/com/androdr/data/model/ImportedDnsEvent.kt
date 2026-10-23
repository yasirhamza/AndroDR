package com.androdr.data.model

/**
 * A dns_event record plus the resolved IPs the [DnsEvent] entity cannot carry
 * (#342). Lives in data/model alongside [NetworkTelemetry] and
 * [SecurityLogEvent]: it is a telemetry value type consumed by the data layer
 * (TimelineAdapter), so keeping it here avoids a data -> scanner dependency
 * inversion.
 */
data class ImportedDnsEvent(
    val event: DnsEvent,
    val resolvedIps: List<String>
) {
    /**
     * The `dns_monitor` record: the live DNS fields plus `resolved_ips`, minus `is_blocked` and
     * `reason`. Those are the tunnel's verdict; AndroDR was not in the path of an import, so the
     * parser's defaults would be fabricated facts (R22).
     */
    fun toFieldMap(): Map<String, Any?> =
        event.toFieldMap() - "is_blocked" - "reason" + ("resolved_ips" to resolvedIps)
}
