package com.androdr.data.store

import com.androdr.data.model.TelemetrySource
import java.io.ByteArrayOutputStream
import java.util.zip.Deflater
import java.util.zip.Inflater

/** A field map after conditional envelope stripping; [strippedKeys] is the bitmask of what was removed. */
data class Stripped(val fields: Map<String, Any?>, val strippedKeys: Int)

/** A stored body: [encoding] 0 plain JSON, 1 Deflate with a preset dictionary; [rawBytes] is its JSON length. */
class EncodedBody(val encoding: Int, val dictVersion: Int, val body: ByteArray, val rawBytes: Int)

/**
 * Turns a telemetry record's field map into a content-addressed body and back (spec §5.1).
 *
 * Snapshot bodies are plain canonical JSON; event bodies are Deflate-compressed against the
 * service's immutable dictionary. `source` and `captured_at` are stripped only when they equal
 * the observation's own values; [Stripped.strippedKeys] records exactly which, so decode
 * restores exactly those.
 */
class TelemetryRecordCodec(private val dictionaries: TelemetryDictionaries) {

    fun strip(fields: Map<String, Any?>, source: TelemetrySource, capturedAt: Long): Stripped {
        var mask = 0
        val out = LinkedHashMap(fields)
        if (fields["source"] == source.name) {
            out.remove("source")
            mask = mask or STRIPPED_SOURCE
        }
        if ((fields["captured_at"] as? Long) == capturedAt) {
            out.remove("captured_at")
            mask = mask or STRIPPED_CAPTURED_AT
        }
        return Stripped(out, mask)
    }

    fun canonicalJson(fields: Map<String, Any?>): String = CanonicalJson.write(fields)

    /** The field map for canonical [json], or null if malformed. */
    fun parse(json: String): Map<String, Any?>? = CanonicalJson.parse(json)

    fun encode(service: String, canonical: String, isEvent: Boolean, deflater: Deflater): EncodedBody {
        val raw = canonical.toByteArray(Charsets.UTF_8)
        if (!isEvent) return EncodedBody(ENCODING_PLAIN, 0, raw, raw.size)
        val (version, dict) = dictionaries.current(service)
        deflater.reset()
        deflater.setDictionary(dict)
        deflater.setInput(raw)
        deflater.finish()
        val out = ByteArrayOutputStream(raw.size / 2 + 16)
        val buf = ByteArray(BUFFER)
        while (!deflater.finished()) out.write(buf, 0, deflater.deflate(buf))
        return EncodedBody(ENCODING_DEFLATE, version, out.toByteArray(), raw.size)
    }

    /** The full field map, or null for a corrupt body or one that does not inflate to exactly [rawBytes]. */
    @Suppress("LongParameterList")
    fun decode(
        body: ByteArray, encoding: Int, dictVersion: Int, rawBytes: Int, strippedKeys: Int,
        source: TelemetrySource, capturedAt: Long,
    ): Map<String, Any?>? {
        if (rawBytes !in 0..MAX_RAW_BYTES || strippedKeys and KNOWN_STRIPPED.inv() != 0) return null
        val raw = try {
            when (encoding) {
                ENCODING_PLAIN -> body.takeIf { it.size == rawBytes }
                ENCODING_DEFLATE -> inflate(body, dictionaries.byVersion(dictVersion), rawBytes)
                else -> null
            }
        } catch (_: java.util.zip.DataFormatException) {
            null
        } catch (_: RuntimeException) {
            // unknown/tampered dictionary, loader I/O or Resources.NotFoundException: unreadable, not fatal
            null
        }
        val parsed = raw?.let { CanonicalJson.parse(String(it, Charsets.UTF_8)) }
        return parsed?.let { restore(it, strippedKeys, source, capturedAt) }
    }

    private fun restore(
        parsed: Map<String, Any?>, strippedKeys: Int, source: TelemetrySource, capturedAt: Long,
    ): Map<String, Any?> {
        val out = LinkedHashMap(parsed)
        if (strippedKeys and STRIPPED_SOURCE != 0) out["source"] = source.name
        if (strippedKeys and STRIPPED_CAPTURED_AT != 0) out["captured_at"] = capturedAt
        return out
    }

    private fun inflate(body: ByteArray, dict: ByteArray, rawBytes: Int): ByteArray? {
        val inflater = Inflater()
        try {
            inflater.setInput(body)
            val out = ByteArray(rawBytes)
            val scratch = ByteArray(1)
            var off = 0
            while (!inflater.finished()) {
                val n = if (off < rawBytes) inflater.inflate(out, off, rawBytes - off) else inflater.inflate(scratch)
                when {
                    n > 0 -> {
                        if (off >= rawBytes) return null
                        off += n
                    }
                    inflater.needsDictionary() -> inflater.setDictionary(dict)
                    !inflater.finished() -> return null
                }
            }
            return out.takeIf { off == rawBytes && inflater.remaining == 0 }
        } finally {
            inflater.end()
        }
    }

    companion object {
        const val ENCODING_PLAIN = 0
        const val ENCODING_DEFLATE = 1
        const val STRIPPED_SOURCE = 1
        const val STRIPPED_CAPTURED_AT = 2
        private const val KNOWN_STRIPPED = STRIPPED_SOURCE or STRIPPED_CAPTURED_AT
        private const val BUFFER = 4096

        /** Sanity cap on a stored body's inflated size; a larger recorded size is treated as corrupt. */
        const val MAX_RAW_BYTES = 16 * 1024 * 1024
    }
}
