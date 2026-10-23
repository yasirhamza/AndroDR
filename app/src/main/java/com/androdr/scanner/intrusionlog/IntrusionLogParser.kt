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

/**
 * Receives each parsed intrusion-log record as it is read, one callback per wrapper type, with its
 * source event key: `"$type $eventId $eventTime"`, or `"$type ? $eventTime"` when the record has no
 * event id. Exact duplicates are not dropped here: the store keeps one fact and one observation per
 * (key, content) and drops the repeat (spec §4.1).
 */
interface IntrusionLogSink {
    suspend fun dns(event: ImportedDnsEvent, key: String)
    suspend fun connect(event: NetworkTelemetry, key: String)
    suspend fun security(event: SecurityLogEvent, key: String)
}

/**
 * What one parse saw besides its records (records past a bound are not counted).
 *
 * @property truncated a per-type record bound ([IntrusionLogParser.MAX_DNS_RECORDS] etc.) dropped at
 *   least one record, so detection did NOT see the complete stream (spec §7).
 */
data class IntrusionLogParseCounts(
    val dnsRecords: Int,
    val connectRecords: Int,
    val securityRecords: Int,
    val malformedLines: Int,
    val truncated: Boolean,
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
 * Each record's source event key is the tuple `(wrapper_type, event_id, event_time)`. event_id
 * alone is unsafe: it may be a per-day counter that restarts at 0, so two genuinely distinct events
 * can share an id; the tuple keeps them apart. A record with no event_id uses
 * `(wrapper_type, ?, event_time)`; the store's fact key adds the content hash, so id-less records
 * with different content stay distinct, while byte-identical within-file and overlapping-file
 * duplicates collapse to one fact and one observation (spec §4.1, S2). The parser keeps no seen-set,
 * so its memory does not grow with the file.
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

    /**
     * Streams every record of [lines] to [sink] (fail-soft per line) and returns the counts. Records
     * past a per-type bound are dropped and set [IntrusionLogParseCounts.truncated].
     */
    @Suppress("TooGenericExceptionCaught") // any per-line parse error means one malformed line, never a failed import
    suspend fun parse(
        lines: Sequence<String>,
        uidResolver: (String) -> Int,
        capturedAt: Long,
        sink: IntrusionLogSink,
        onLine: () -> Unit = {},
    ): IntrusionLogParseCounts {
        val counts = IntArray(TYPE_COUNT)
        var malformed = 0
        var truncated = false

        for (rawLine in lines) {
            // Cooperative cancellation: propagates CancellationException out of
            // parse() so leaving the screen stops a huge import. Must run before
            // the per-line try/catch, which would otherwise swallow it as
            // "malformed". ensureActive() (the caller's check) is a cheap
            // volatile read, so a per-line cadence is fine.
            onLine()
            if (rawLine.isBlank()) continue // blank lines are ignored silently
            // Bound line length before any work; an over-long line (e.g. a
            // crafted ZIP with one multi-MB unterminated "line") is counted
            // malformed and never parsed, so it cannot blow memory here.
            val record = if (rawLine.length > maxLineLength) {
                null
            } else {
                try {
                    parseLine(rawLine.trim(), uidResolver, capturedAt)
                } catch (_: Exception) {
                    null
                }
            }
            when {
                record == null -> malformed++
                counts[record.type] >= capOf(record.type) -> truncated = true
                else -> {
                    counts[record.type]++
                    // Outside the per-line catch: a sink (writer) failure fails the import.
                    emit(record, sink)
                }
            }
        }
        return IntrusionLogParseCounts(counts[DNS], counts[CONNECT], counts[SECURITY], malformed, truncated)
    }

    private class Parsed(val type: Int, val event: Any, val key: String)

    private fun capOf(type: Int): Int = when (type) {
        DNS -> maxDnsRecords
        CONNECT -> maxConnectRecords
        else -> maxSecurityRecords
    }

    private suspend fun emit(record: Parsed, sink: IntrusionLogSink) = when (record.type) {
        DNS -> sink.dns(record.event as ImportedDnsEvent, record.key)
        CONNECT -> sink.connect(record.event as NetworkTelemetry, record.key)
        else -> sink.security(record.event as SecurityLogEvent, record.key)
    }

    private fun parseLine(line: String, uidResolver: (String) -> Int, capturedAt: Long): Parsed {
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

        // A record missing its DEFINING payload (a dns_event without a hostname, a
        // connect_event without an ip_address or port) throws here and is caught as
        // malformed — never emitted as a phantom row that inflates the event counts.
        // Secondary fields (package_name, resolved ip_addresses[], and ALL of
        // security_event) keep their lenient sentinels so security_log never
        // regresses to shipping dead.
        val eventId = body["event_id"]?.jsonPrimitive?.longOrNull
        val key = if (eventId != null) "$type $eventId $eventTime" else "$type ? $eventTime"
        return when (type) {
            "dns_event" -> Parsed(DNS, parseDnsEvent(body, eventTime, uidResolver), key)
            "connect_event" -> Parsed(CONNECT, parseConnectEvent(body, eventTime, uidResolver, capturedAt), key)
            else -> Parsed(SECURITY, parseSecurityEvent(body, eventTime, capturedAt), key)
        }
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
        // RFC 1035: no hostname exceeds 253 characters. Longer ones are malformed, and
        // dropping them bounds what a crafted export can push into detection (B5).
        require(domain.length <= MAX_HOSTNAME_LENGTH) { "dns_event hostname longer than $MAX_HOSTNAME_LENGTH" }
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

    companion object {
        private const val DNS = 0
        private const val CONNECT = 1
        private const val SECURITY = 2
        private const val TYPE_COUNT = 3

        private val KNOWN_WRAPPERS = setOf("dns_event", "connect_event", "security_event")

        /** Wrapper-body keys that are envelope metadata, never the tag-name payload key. */
        private val EVENT_META_KEYS = setOf("event_id", "event_time")

        /** At/above this an `event_time` is nanoseconds, not milliseconds (1e15). */
        private const val NANOSECOND_FLOOR = 1_000_000_000_000_000L
        private const val NANOS_PER_MILLI = 1_000_000L

        /** 1 MiB. A single JSONL record is far smaller; anything larger is crafted. */
        private const val MAX_LINE_LENGTH = 1_048_576

        /**
         * Per-type input bounds (spec §5.2 Input bounds). Records stream through the writer session
         * in chunks, so memory no longer grows with them; a bound only stops a pathological file
         * from filling the disk, and a tripped bound is reported (`truncated`).
         * Distinct from ScanOrchestrator's much smaller Timeline-row caps.
         */
        const val MAX_DNS_RECORDS = 2_000_000
        const val MAX_CONNECT_RECORDS = 2_000_000
        const val MAX_SECURITY_RECORDS = 2_000_000

        /** Per-field length bound (covers 253-char hostnames / 255-char packages). */
        private const val MAX_FIELD_LENGTH = 4_096

        /** RFC 1035 maximum length of a hostname in text form. */
        private const val MAX_HOSTNAME_LENGTH = 253

        /** 2008-01-01T00:00:00Z — predates any Android device; nothing earlier is real. */
        private const val MIN_EVENT_TIME_MS = 1_199_145_600_000L

        /** Import wall-clock (capturedAt) + skew is the future ceiling; rejects Long.MAX pins. */
        private const val MAX_CLOCK_SKEW_MS = 5L * 60_000L
    }
}
