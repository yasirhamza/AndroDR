package com.androdr.sigma

import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent

/**
 * Projects intrusion-log telemetry to [StoreRecord]s through each type's `toFieldMap()`. [keys], when
 * given, holds each record's source event key index for index (`IntrusionLogParser`'s
 * `"$type $eventId $eventTime"` / `"$type ? $eventTime"`).
 */
object IntrusionLogRecordBuilders {
    const val DNS_MONITOR = "dns_monitor"
    const val NETWORK_MONITOR = "network_monitor"
    const val SECURITY_LOG = "security_log"

    /** The live DNS fields plus `resolved_ips`. */
    fun importedDns(t: List<ImportedDnsEvent>, keys: List<String>? = null): List<StoreRecord> =
        t.mapIndexed { i, e -> StoreRecord(e.toFieldMap(), keys?.get(i)) }
    fun network(t: List<NetworkTelemetry>, keys: List<String>? = null): List<StoreRecord> =
        t.mapIndexed { i, e -> StoreRecord(e.toFieldMap(), keys?.get(i)) }
    fun securityLog(t: List<SecurityLogEvent>, keys: List<String>? = null): List<StoreRecord> =
        t.mapIndexed { i, e -> StoreRecord(e.toFieldMap(), keys?.get(i)) }
}
