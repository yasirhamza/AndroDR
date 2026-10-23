package com.androdr.scanner.intrusionlog

import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import kotlinx.coroutines.runBlocking

/**
 * Test-only: everything one [IntrusionLogParser.parse] streamed, collected into lists with each
 * record's source event key. Production never collects a whole import (spec §5.2).
 */
internal data class ParsedIntrusionLog(
    val dnsEvents: List<ImportedDnsEvent>,
    val networkEvents: List<NetworkTelemetry>,
    val securityEvents: List<SecurityLogEvent>,
    val dnsKeys: List<String>,
    val networkKeys: List<String>,
    val securityKeys: List<String>,
    val malformedLines: Int,
    val truncated: Boolean,
)

/** Collects a parse into a [ParsedIntrusionLog] (test convenience over the streaming sink). */
internal fun IntrusionLogParser.parse(
    lines: Sequence<String>,
    uidResolver: (String) -> Int,
    capturedAt: Long,
    onLine: () -> Unit = {},
): ParsedIntrusionLog {
    val dns = mutableListOf<ImportedDnsEvent>()
    val net = mutableListOf<NetworkTelemetry>()
    val sec = mutableListOf<SecurityLogEvent>()
    val dnsKeys = mutableListOf<String>()
    val netKeys = mutableListOf<String>()
    val secKeys = mutableListOf<String>()
    val sink = object : IntrusionLogSink {
        override suspend fun dns(event: ImportedDnsEvent, key: String) { dns += event; dnsKeys += key }
        override suspend fun connect(event: NetworkTelemetry, key: String) { net += event; netKeys += key }
        override suspend fun security(event: SecurityLogEvent, key: String) { sec += event; secKeys += key }
    }
    val counts = runBlocking { parse(lines, uidResolver, capturedAt, sink, onLine) }
    return ParsedIntrusionLog(dns, net, sec, dnsKeys, netKeys, secKeys, counts.malformedLines, counts.truncated)
}
