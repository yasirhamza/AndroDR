package com.androdr.data.store

import com.androdr.reporting.isUnsafeCodePoint
import java.util.Locale

/**
 * One line of the telemetry JSONL export (spec §7): one JSON envelope per observation.
 *
 * Envelope keys: `scan_id`, `service`, `ordinal`, `fact_id`, `source`, `captured_at` (the
 * observation's own envelope), `event_time`, `time_precision`, `category`, `subject_key`,
 * `unreadable`, and `fields`. `fields` is the record as stored, with the envelope keys storage
 * stripped (`source`, `captured_at`, per the observation's stripped-key mask) restored by decode, in
 * the store's canonical type-exact JSON ([CanonicalJson]: sorted keys, `~L`/`~D`/`~B`/`~S` tags).
 * An unreadable body (spec §5.1) still gets its line: `fields` is null and `unreadable` is true.
 *
 * Every character in Unicode categories Cc, Cf, Zl, Zp, Co, Cn and Cs is written as a `\uXXXX`
 * escape (spec §7 escaping), so no value can break a line (U+2028 included) or carry a bidi override.
 */
internal object TelemetryJsonl {

    fun line(r: DecodedRecord): String {
        val sb = StringBuilder()
        sb.append("{\"captured_at\":").append(r.capturedAt)
        sb.append(",\"category\":").append(r.category?.let(CanonicalJson::quote) ?: "null")
        sb.append(",\"event_time\":").append(r.eventTime?.toString() ?: "null")
        sb.append(",\"fact_id\":").append(r.factId)
        sb.append(",\"fields\":").append(r.fields?.let(CanonicalJson::write) ?: "null")
        sb.append(",\"ordinal\":").append(r.ordinal)
        sb.append(",\"scan_id\":").append(r.scanId)
        sb.append(",\"service\":").append(CanonicalJson.quote(r.service))
        sb.append(",\"source\":").append(CanonicalJson.quote(r.source.name))
        sb.append(",\"subject_key\":").append(r.subjectKey?.let(CanonicalJson::quote) ?: "null")
        sb.append(",\"time_precision\":").append(CanonicalJson.quote(r.precision.name))
        sb.append(",\"unreadable\":").append(r.fields == null)
        sb.append('}')
        return escapeUnsafe(sb)
    }

    /**
     * Rewrites every unsafe character of [json] as `\uXXXX` (a pair as its two escaped units). They
     * can only occur inside JSON strings ([CanonicalJson] writes structure in ASCII), where the escape
     * decodes to the same character, so the JSON value is unchanged.
     */
    private fun escapeUnsafe(json: CharSequence): String {
        val out = StringBuilder(json.length)
        var i = 0
        while (i < json.length) {
            val c = json[i]
            val pair = c.isHighSurrogate() && i + 1 < json.length && json[i + 1].isLowSurrogate()
            val width = if (pair) 2 else 1
            val cp = if (pair) Character.toCodePoint(c, json[i + 1]) else c.code
            if (isUnsafeCodePoint(cp)) {
                for (j in i until i + width) out.append("\\u").append(String.format(Locale.US, "%04X", json[j].code))
            } else {
                out.append(json, i, i + width)
            }
            i += width
        }
        return out.toString()
    }
}
