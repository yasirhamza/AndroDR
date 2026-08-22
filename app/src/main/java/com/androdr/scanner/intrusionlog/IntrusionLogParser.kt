package com.androdr.scanner.intrusionlog

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/** A dns_event record plus the resolved IPs the DnsEvent entity cannot carry. */
data class ImportedDnsEvent(
    val event: DnsEvent,
    val resolvedIps: List<String>
)

data class ParsedIntrusionLog(
    val dnsEvents: List<ImportedDnsEvent>,
    val networkEvents: List<NetworkTelemetry>,
    val securityEvents: List<SecurityLogEvent>,
    val duplicatesCollapsed: Int,
    val malformedLines: Int
)

/**
 * Parses Advanced Protection Intrusion Logging JSONL (#342, spec §3).
 * Pure emitter: emits every fact verbatim, constructs no findings.
 * Fail-soft per line; dedup on the type-shared monotonic event_id,
 * first-seen across the whole (multi-file) sequence.
 */
class IntrusionLogParser {

    private companion object {
        val KNOWN_WRAPPERS = setOf("dns_event", "connect_event", "security_event")
    }

    private val json = Json { ignoreUnknownKeys = true }

    @Suppress("TooGenericExceptionCaught") // any per-line parse error means one malformed line, never a failed import
    fun parse(
        lines: Sequence<String>,
        uidResolver: (String) -> Int,
        capturedAt: Long
    ): ParsedIntrusionLog {
        val dns = mutableListOf<ImportedDnsEvent>()
        val net = mutableListOf<NetworkTelemetry>()
        val sec = mutableListOf<SecurityLogEvent>()
        val seenEventIds = HashSet<Long>()
        var duplicates = 0
        var malformed = 0

        for (rawLine in lines) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            try {
                val outcome = processLine(line, uidResolver, capturedAt, seenEventIds, dns, net, sec)
                if (outcome == LineOutcome.DUPLICATE) duplicates++
            } catch (_: Exception) {
                malformed++
            }
        }
        return ParsedIntrusionLog(dns, net, sec, duplicates, malformed)
    }

    private enum class LineOutcome { PROCESSED, DUPLICATE }

    private fun processLine(
        line: String,
        uidResolver: (String) -> Int,
        capturedAt: Long,
        seenEventIds: MutableSet<Long>,
        dns: MutableList<ImportedDnsEvent>,
        net: MutableList<NetworkTelemetry>,
        sec: MutableList<SecurityLogEvent>
    ): LineOutcome {
        val root = json.parseToJsonElement(line).jsonObject
        val entry = root.entries.firstOrNull() ?: throw IllegalArgumentException("empty object")
        val body = entry.value.jsonObject
        val eventId = body["event_id"]!!.jsonPrimitive.long
        require(entry.key in KNOWN_WRAPPERS) { "unknown wrapper ${entry.key}" }
        if (!seenEventIds.add(eventId)) return LineOutcome.DUPLICATE

        val eventTime = body["event_time"]!!.jsonPrimitive.long
        when (entry.key) {
            "dns_event" -> dns += parseDnsEvent(body, eventTime, uidResolver)
            "connect_event" -> net += parseConnectEvent(body, eventTime, uidResolver, capturedAt)
            "security_event" -> sec += parseSecurityEvent(body, eventTime, capturedAt)
        }
        return LineOutcome.PROCESSED
    }

    private fun parseDnsEvent(
        body: JsonObject,
        eventTime: Long,
        uidResolver: (String) -> Int
    ): ImportedDnsEvent {
        val pkg = body["package_name"]?.jsonPrimitive?.contentOrNull
        return ImportedDnsEvent(
            event = DnsEvent(
                timestamp = eventTime,
                domain = body["hostname"]!!.jsonPrimitive.content,
                appUid = pkg?.let(uidResolver) ?: -1,
                appName = pkg,
                isBlocked = false,
                reason = null
            ),
            resolvedIps = body["ip_addresses"]?.jsonArray
                ?.map { stripIpPrefix(it.jsonPrimitive.content) }
                .orEmpty()
        )
    }

    private fun parseConnectEvent(
        body: JsonObject,
        eventTime: Long,
        uidResolver: (String) -> Int,
        capturedAt: Long
    ): NetworkTelemetry {
        val pkg = body["package_name"]?.jsonPrimitive?.contentOrNull
        return NetworkTelemetry(
            destinationIp = stripIpPrefix(body["ip_address"]!!.jsonPrimitive.content),
            destinationPort = body["port"]!!.jsonPrimitive.int,
            protocol = null, // genuinely absent from the source (spec §3)
            appUid = pkg?.let(uidResolver) ?: -1,
            appName = pkg,
            timestamp = eventTime,
            source = TelemetrySource.INTRUSION_LOG_IMPORT,
            capturedAt = capturedAt
        )
    }

    private fun parseSecurityEvent(
        body: JsonObject,
        eventTime: Long,
        capturedAt: Long
    ): SecurityLogEvent {
        val tag = body["tag"]!!.jsonPrimitive.int
        return SecurityLogEvent(
            timestamp = eventTime,
            tag = tag,
            tagName = SecurityLogTagRegistry.nameFor(tag),
            securityData = body["data"]?.jsonArray
                ?.map { it.jsonPrimitive.content }
                .orEmpty(),
            source = TelemetrySource.INTRUSION_LOG_IMPORT,
            capturedAt = capturedAt
        )
    }

    /** Java InetAddress.toString() renders "hostname/literal"; exports show "/1.2.3.4". */
    private fun stripIpPrefix(raw: String): String = raw.substringAfterLast('/')
}
