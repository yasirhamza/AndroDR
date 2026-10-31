package com.androdr.scanner

import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.sigma.Finding
import com.androdr.sigma.IntrusionLogRecordBuilders
import com.androdr.sigma.LiveRecordBuilders
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.StoreRecord

/**
 * Test-only [IntrusionLogChunks]: collects every chunk the analyzer hands over, and — when given an
 * [engine] — evaluates each one the way the writer session does (per-service ordinals), so analyzer
 * tests can check what detection saw without a database.
 */
internal class CollectingChunks(private val engine: SigmaRuleEngine? = null) : IntrusionLogChunks {
    val dnsEvents = mutableListOf<ImportedDnsEvent>()
    val networkEvents = mutableListOf<NetworkTelemetry>()
    val securityEvents = mutableListOf<SecurityLogEvent>()
    val records = mutableMapOf<String, MutableList<StoreRecord>>()
    val chunkSizes = mutableListOf<Pair<String, Int>>()
    val findings = mutableListOf<Finding>()

    override suspend fun dns(events: List<ImportedDnsEvent>, records: List<StoreRecord>) {
        dnsEvents += events
        take(LiveRecordBuilders.DNS_MONITOR, records)
    }

    override suspend fun connect(events: List<NetworkTelemetry>, records: List<StoreRecord>) {
        networkEvents += events
        take(IntrusionLogRecordBuilders.NETWORK_MONITOR, records)
    }

    override suspend fun security(events: List<SecurityLogEvent>, records: List<StoreRecord>) {
        securityEvents += events
        take(IntrusionLogRecordBuilders.SECURITY_LOG, records)
    }

    private fun take(service: String, chunk: List<StoreRecord>) {
        val all = records.getOrPut(service) { mutableListOf() }
        chunkSizes += service to chunk.size
        engine?.let { findings += it.evaluateRecords(service, chunk, all.size) }
        all += chunk
    }
}
