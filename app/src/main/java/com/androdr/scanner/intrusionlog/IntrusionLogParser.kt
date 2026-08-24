package com.androdr.scanner.intrusionlog

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

data class ParsedIntrusionLog(
    val dnsEvents: List<ImportedDnsEvent>,
    val networkEvents: List<NetworkTelemetry>,
    val securityEvents: List<SecurityLogEvent>,
    val duplicatesCollapsed: Int,
    val malformedLines: Int,
    /**
     * True when a per-type record cap ([MAX_DNS_RECORDS] etc.) or the line-length
     * bound dropped at least one record. When set, detection did NOT see the
     * complete stream — the "detection sees everything" invariant (spec §7) is
     * not guaranteed for this file, so callers must not assume completeness.
     */
    val truncated: Boolean = false
)

/**
 * Parses Advanced Protection Intrusion Logging JSONL (#342, spec §3).
 * Pure emitter: emits every fact verbatim, constructs no findings.
 *
 * Fail-soft per line: a line is counted malformed and skipped — never a failed
 * import — when it is not valid JSON, lacks the wrapper / event_time, carries an
 * out-of-window event_time, or lacks its record's DEFINING payload (a dns_event
 * without a hostname, a connect_event without an ip_address or port), which would
 * otherwise become a phantom row inflating the event counts. Missing SECONDARY
 * fields (including event_id, package_name, resolved ip_addresses[], and every
 * security_event field) do NOT drop a record; they fall back to sentinels so the
 * fact still reaches the engine (emitters-emit-all-facts, spec §4.2).
 *
 * Dedup is on the tuple `(event_id, event_time, wrapper_type)` — first-seen
 * across the whole (multi-file) sequence. event_id alone is unsafe: it may be a
 * per-day counter that restarts at 0, so two genuinely distinct events can share
 * an id; the tuple keeps them apart while still collapsing byte-identical
 * within-file and overlapping-file duplicates (which share all three). Records
 * with no event_id fall back to `(wrapper_type, event_time, content-hash)`.
 *
 * Hardening (#342 review): caps line length, per-type record counts, and every
 * ingested string field's length; sanitizes CR/LF and C0 control characters out
 * of ip/hostname/package/security-data so they cannot forge report sections;
 * validates event_time against a sane window; and calls [onLine] each iteration
 * so a cancelled coroutine stops the parse promptly.
 */
class IntrusionLogParser(
    private val maxLineLength: Int = MAX_LINE_LENGTH,
    private val maxDnsRecords: Int = MAX_DNS_RECORDS,
    private val maxConnectRecords: Int = MAX_CONNECT_RECORDS,
    private val maxSecurityRecords: Int = MAX_SECURITY_RECORDS
) {

    @Suppress("TooGenericExceptionCaught") // any per-line parse error means one malformed line, never a failed import
    fun parse(
        lines: Sequence<String>,
        uidResolver: (String) -> Int,
        capturedAt: Long,
        onLine: () -> Unit = {}
    ): ParsedIntrusionLog {
        val dns = mutableListOf<ImportedDnsEvent>()
        val net = mutableListOf<NetworkTelemetry>()
        val sec = mutableListOf<SecurityLogEvent>()
        val seenKeys = HashSet<String>()
        var duplicates = 0
        var malformed = 0
        var truncated = false

        for (rawLine in lines) {
            // Cooperative cancellation: propagates CancellationException out of
            // parse() so leaving the screen stops a huge import. Must run before
            // the per-line try/catch, which would otherwise swallow it as
            // "malformed". ensureActive() (the caller's check) is a cheap
            // volatile read, so a per-line cadence is fine.
            onLine()
            when {
                // Bound line length before any work; an over-long line (e.g. a
                // crafted ZIP with one multi-MB unterminated "line") is counted
                // malformed and never parsed, so it cannot blow memory here.
                rawLine.length > maxLineLength -> malformed++
                rawLine.isBlank() -> Unit // blank lines are ignored silently
                else -> try {
                    when (processLine(rawLine.trim(), uidResolver, capturedAt, seenKeys, dns, net, sec)) {
                        LineOutcome.DUPLICATE -> duplicates++
                        LineOutcome.TRUNCATED -> truncated = true
                        LineOutcome.PROCESSED -> Unit
                    }
                } catch (_: Exception) {
                    malformed++
                }
            }
        }
        return ParsedIntrusionLog(dns, net, sec, duplicates, malformed, truncated)
    }

    private enum class LineOutcome { PROCESSED, DUPLICATE, TRUNCATED }

    private fun processLine(
        line: String,
        uidResolver: (String) -> Int,
        capturedAt: Long,
        seenKeys: MutableSet<String>,
        dns: MutableList<ImportedDnsEvent>,
        net: MutableList<NetworkTelemetry>,
        sec: MutableList<SecurityLogEvent>
    ): LineOutcome {
        // Only parseToJsonElement is used, which ignores decode-time config
        // (ignoreUnknownKeys is inert here), so the default Json instance suffices.
        val root = Json.parseToJsonElement(line).jsonObject
        val entry = root.entries.firstOrNull() ?: throw IllegalArgumentException("empty object")
        val type = entry.key
        require(type in KNOWN_WRAPPERS) { "unknown wrapper $type" }
        val body = entry.value.jsonObject

        // event_time is the one required numeric field; a missing/non-numeric or
        // out-of-window value marks the whole line malformed (throws -> caught).
        // Real exports mix UNITS across wrapper types, so normalize first and
        // validate the normalized value (#356).
        val rawEventTime = body["event_time"]?.jsonPrimitive?.longOrNull
            ?: throw IllegalArgumentException("missing event_time")
        val eventTime = normalizeToMillis(rawEventTime)
        require(eventTime in MIN_EVENT_TIME_MS..(capturedAt + MAX_CLOCK_SKEW_MS)) {
            "event_time $rawEventTime out of window"
        }

        // Cap BEFORE dedup so a truncated type never pollutes the seen-set.
        val capReached = when (type) {
            "dns_event" -> dns.size >= maxDnsRecords
            "connect_event" -> net.size >= maxConnectRecords
            else -> sec.size >= maxSecurityRecords
        }
        if (capReached) return LineOutcome.TRUNCATED

        // Build the record now. A record missing its DEFINING payload (a
        // dns_event without a hostname, a connect_event without an ip_address or
        // port) throws here and is caught as malformed — never emitted as a
        // phantom row that inflates the event counts. Building before the dedup
        // add means such a record never touches the seen-set, so it cannot mask
        // a later good record as a "duplicate". Secondary fields (package_name,
        // resolved ip_addresses[], and ALL of security_event) keep their lenient
        // sentinels so security_log never regresses to shipping dead.
        val dnsEvent: ImportedDnsEvent?
        val netEvent: NetworkTelemetry?
        val secEvent: SecurityLogEvent?
        when (type) {
            "dns_event" -> {
                dnsEvent = parseDnsEvent(body, eventTime, uidResolver); netEvent = null; secEvent = null
            }
            "connect_event" -> {
                netEvent = parseConnectEvent(body, eventTime, uidResolver, capturedAt); dnsEvent = null; secEvent = null
            }
            else -> {
                secEvent = parseSecurityEvent(body, eventTime, capturedAt); dnsEvent = null; netEvent = null
            }
        }

        val eventId = body["event_id"]?.jsonPrimitive?.longOrNull
        val dedupKey = if (eventId != null) {
            "$type $eventId $eventTime"
        } else {
            // No id: synthesize a stable identity so byte-identical records still
            // collapse while distinct records (different content) are kept.
            "$type ? $eventTime ${line.hashCode()}"
        }
        if (!seenKeys.add(dedupKey)) return LineOutcome.DUPLICATE

        dnsEvent?.let { dns += it }
        netEvent?.let { net += it }
        secEvent?.let { sec += it }
        return LineOutcome.PROCESSED
    }

    private fun parseDnsEvent(
        body: JsonObject,
        eventTime: Long,
        uidResolver: (String) -> Int
    ): ImportedDnsEvent {
        val pkg = body.sanitizedString("package_name")
        // hostname is the record's defining payload: sanitize FIRST (so a
        // control-char-only value collapses to blank), then require non-blank —
        // an absent/blank hostname is malformed, not an empty-domain phantom row.
        val domain = body.sanitizedString("hostname")
        require(!domain.isNullOrBlank()) { "dns_event without hostname" }
        return ImportedDnsEvent(
            event = DnsEvent(
                timestamp = eventTime,
                domain = domain,
                appUid = pkg?.let(uidResolver) ?: -1,
                appName = pkg,
                isBlocked = false,
                reason = null
            ),
            resolvedIps = (body["ip_addresses"] as? JsonArray)
                ?.map { sanitize(stripIpPrefix(stringify(it))) }
                .orEmpty()
        )
    }

    private fun parseConnectEvent(
        body: JsonObject,
        eventTime: Long,
        uidResolver: (String) -> Int,
        capturedAt: Long
    ): NetworkTelemetry {
        val pkg = body.sanitizedString("package_name")
        // ip_address + port are the record's defining payload: strip+sanitize the
        // ip FIRST, then require a non-blank ip and a present port — a
        // connect_event missing either is malformed, not a blank-destination
        // phantom row.
        val destinationIp = body["ip_address"]?.let { sanitize(stripIpPrefix(stringify(it))) }
        require(!destinationIp.isNullOrBlank()) { "connect_event without ip_address" }
        val destinationPort = body["port"]?.jsonPrimitive?.intOrNull
        requireNotNull(destinationPort) { "connect_event without port" }
        return NetworkTelemetry(
            destinationIp = destinationIp,
            destinationPort = destinationPort,
            protocol = null, // genuinely absent from the source (spec §3)
            appUid = pkg?.let(uidResolver) ?: -1,
            appName = pkg,
            timestamp = eventTime,
            source = TelemetrySource.INTRUSION_LOG_IMPORT,
            capturedAt = capturedAt
        )
    }

    /**
     * Two shapes reach here (#356):
     *
     *  - the MVT-documented one, `{"tag":210002,"data":["…"]}` — a numeric tag
     *    plus a positional array. No sampled Samsung/Pixel export emits it, but
     *    another OEM may, so it stays as the fallback path;
     *  - the shape a REAL Android 16 export emits: no `tag`, no `data`. The one
     *    key besides `event_id`/`event_time` IS the tag name in snake_case, and
     *    its value is an object of NAMED fields (sometimes empty `{}`), e.g.
     *    `"app_process_start":{"process":"…","uid":99219,…}`.
     *
     * The named fields are rendered as sorted `key=value` strings so the shared
     * [SecurityLogEvent.securityData] stays a `List<String>` for both shapes and
     * rules can match on `key=` prefixes deterministically. An unregistered tag
     * name keeps its name with tag [SecurityLogTagRegistry.UNKNOWN_TAG]; a body
     * with no payload key at all is still EMITTED (emitters emit all facts —
     * dropping it would hide the fact that an event occurred at all).
     */
    private fun parseSecurityEvent(
        body: JsonObject,
        eventTime: Long,
        capturedAt: Long
    ): SecurityLogEvent {
        val numericTag = body["tag"]?.jsonPrimitive?.intOrNull
        val tag: Int
        val tagName: String
        val securityData: List<String>
        if (numericTag != null) {
            tag = numericTag
            tagName = SecurityLogTagRegistry.nameFor(numericTag)
            val dataEl = body["data"]
            securityData = when {
                dataEl is JsonArray -> dataEl.map { sanitize(stringify(it)) }
                dataEl == null || dataEl is JsonNull -> emptyList()
                else -> listOf(sanitize(stringify(dataEl)))
            }
        } else {
            val payload = body.entries.firstOrNull { it.key !in EVENT_META_KEYS }
            tag = payload?.let { SecurityLogTagRegistry.idFor(it.key) }
                ?: SecurityLogTagRegistry.UNKNOWN_TAG
            tagName = payload?.key ?: SecurityLogTagRegistry.nameFor(SecurityLogTagRegistry.UNKNOWN_TAG)
            securityData = when (val value = payload?.value) {
                null, is JsonNull -> emptyList()
                is JsonObject -> value.entries
                    .map { (key, el) -> sanitize("$key=${stringify(el)}") }
                    .sorted()
                else -> listOf(sanitize(stringify(value)))
            }
        }
        return SecurityLogEvent(
            timestamp = eventTime,
            tag = tag,
            tagName = tagName,
            securityData = securityData,
            source = TelemetrySource.INTRUSION_LOG_IMPORT,
            capturedAt = capturedAt
        )
    }

    /**
     * Normalizes an `event_time` to epoch MILLISECONDS. Real exports mix units:
     * `security_event` stamps epoch NANOSECONDS (~1.79e18) while `dns_event` /
     * `connect_event` stamp epoch milliseconds (~1.79e12) (#356). A value at or
     * above [NANOSECOND_FLOOR] (1e15 ms would be the year 33658 — unreachable as
     * a real epoch-ms value, and every epoch-ns value since 2001 exceeds it) is
     * therefore nanoseconds and is divided down. Applied per RECORD, so a file
     * mixing both units normalizes line by line; the sanity window then runs on
     * the normalized value, so an absurd timestamp is still rejected.
     */
    private fun normalizeToMillis(raw: Long): Long =
        if (raw >= NANOSECOND_FLOOR) raw / NANOS_PER_MILLI else raw

    /** Reads a string field, sanitized; null when the key is absent or JSON null. */
    private fun JsonObject.sanitizedString(key: String): String? =
        this[key]?.takeUnless { it is JsonNull }?.let { sanitize(stringify(it)) }

    /**
     * Renders any JSON element to a String: primitives to their content, nested
     * arrays/objects to their JSON text (emitters-emit-all-facts, spec §4.2 —
     * never throw on a non-primitive).
     */
    private fun stringify(el: JsonElement): String = when (el) {
        is JsonPrimitive -> el.contentOrNull ?: el.toString()
        else -> el.toString()
    }

    /**
     * Neutralizes ingested string fields before they flow into the shared
     * plaintext report: replaces CR/LF and all C0 control characters (plus DEL)
     * with a space so a crafted hostname/ip/package/data value cannot forge a
     * newline-delimited FINDINGS section, and bounds the field length.
     */
    private fun sanitize(raw: String): String {
        val bounded = if (raw.length > MAX_FIELD_LENGTH) raw.substring(0, MAX_FIELD_LENGTH) else raw
        return buildString(bounded.length) {
            for (c in bounded) {
                append(if (c.code < 0x20 || c.code == 0x7F) ' ' else c)
            }
        }
    }

    /** Java InetAddress.toString() renders "hostname/literal"; exports show "/1.2.3.4". */
    private fun stripIpPrefix(raw: String): String = raw.substringAfterLast('/')

    private companion object {
        val KNOWN_WRAPPERS = setOf("dns_event", "connect_event", "security_event")

        /** Wrapper-body keys that are envelope metadata, never the tag-name payload key. */
        val EVENT_META_KEYS = setOf("event_id", "event_time")

        /** At/above this an `event_time` is nanoseconds, not milliseconds (1e15). */
        const val NANOSECOND_FLOOR = 1_000_000_000_000_000L
        const val NANOS_PER_MILLI = 1_000_000L

        /** 1 MiB. A single JSONL record is far smaller; anything larger is crafted. */
        const val MAX_LINE_LENGTH = 1_048_576

        /**
         * Per-type record caps. Detection normally sees the complete stream
         * (spec §7), but an unbounded pathological file would OOM; 200k events
         * per type dwarfs any real export while bounding worst-case memory.
         * Distinct from ScanOrchestrator's much smaller persistence caps.
         */
        const val MAX_DNS_RECORDS = 200_000
        const val MAX_CONNECT_RECORDS = 200_000
        const val MAX_SECURITY_RECORDS = 200_000

        /** Per-field length bound (covers 253-char hostnames / 255-char packages). */
        const val MAX_FIELD_LENGTH = 4_096

        /** 2008-01-01T00:00:00Z — predates any Android device; nothing earlier is real. */
        const val MIN_EVENT_TIME_MS = 1_199_145_600_000L

        /** Import wall-clock (capturedAt) + skew is the future ceiling; rejects Long.MAX pins. */
        const val MAX_CLOCK_SKEW_MS = 5L * 60_000L
    }
}
