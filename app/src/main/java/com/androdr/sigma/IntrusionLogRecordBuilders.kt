package com.androdr.sigma

import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent

/** Projects intrusion-log telemetry to [StoreRecord]s through each type's `toFieldMap()`. */
object IntrusionLogRecordBuilders {
    const val DNS_MONITOR = "dns_monitor"
    const val NETWORK_MONITOR = "network_monitor"
    const val SECURITY_LOG = "security_log"

    /** The live DNS fields plus `resolved_ips`. */
    fun importedDns(t: List<ImportedDnsEvent>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun network(t: List<NetworkTelemetry>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun securityLog(t: List<SecurityLogEvent>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
}
