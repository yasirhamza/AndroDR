package com.androdr.data.store

import java.util.Base64

/**
 * Canonical, type-exact JSON for telemetry field maps.
 *
 * Canonical: object keys sorted, no whitespace, sets sorted by their encoded form, so equal
 * content always yields equal bytes (and hash). Exact: types that plain JSON would blur are
 * tagged as single-key objects (`~L` Long that fits an Int, `~D` NaN/Infinity, `~B` bytes as
 * base64, `~S` set). A real map key starting with `~` is escaped with another `~`.
 * Integers outside the Int range are plain numbers that decode as Long; Short/Byte decode as
 * Int, Float as Double, enums as their name.
 */
internal object CanonicalJson {
    private const val MAX_DEPTH = 64
    private val TAGS = setOf("~L", "~D", "~B", "~S")

    fun write(fields: Map<String, Any?>): String = StringBuilder().also { writeMap(fields, it) }.toString()

    /** [s] as a JSON string literal, escaped exactly as [write] escapes strings. */
    fun quote(s: String): String = StringBuilder().also { writeString(s, it) }.toString()

    /** The decoded map, or null if [json] is not a well-formed canonical object. */
    fun parse(json: String): Map<String, Any?>? = try {
        val p = Parser(json)
        val v = p.value(0)
        p.skipEnd()
        @Suppress("UNCHECKED_CAST")
        v as? Map<String, Any?>
    } catch (_: ParseFailure) {
        null
    }

    // ---- writer ----------------------------------------------------------------------------

    private fun writeValue(v: Any?, out: StringBuilder) {
        when (v) {
            null -> out.append("null")
            is Boolean -> out.append(v)
            is Int -> out.append(v)
            is Short, is Byte -> out.append((v as Number).toInt())
            is Long ->
                if (v in Int.MIN_VALUE..Int.MAX_VALUE) out.append("{\"~L\":").append(v).append('}') else out.append(v)
            is Double -> writeDouble(v, out)
            is Float -> writeDouble(v.toDouble(), out)
            is String -> writeString(v, out)
            is Enum<*> -> writeString(v.name, out)
            is ByteArray -> out.append("{\"~B\":\"").append(Base64.getEncoder().encodeToString(v)).append("\"}")
            is Map<*, *> -> writeMap(v, out)
            is Set<*> -> {
                val items = v.map { StringBuilder().also { sb -> writeValue(it, sb) }.toString() }.sorted()
                out.append("{\"~S\":[").append(items.joinToString(",")).append("]}")
            }
            is List<*> -> {
                out.append('[')
                v.forEachIndexed { i, e ->
                    if (i > 0) out.append(',')
                    writeValue(e, out)
                }
                out.append(']')
            }
            else -> throw IllegalArgumentException("unsupported telemetry value type ${v.javaClass.name}")
        }
    }

    private fun writeDouble(d: Double, out: StringBuilder) {
        if (d.isNaN() || d.isInfinite()) out.append("{\"~D\":\"").append(d).append("\"}") else out.append(d)
    }

    private fun writeMap(m: Map<*, *>, out: StringBuilder) {
        out.append('{')
        val keys = m.keys.map { it.toString() to it }.sortedBy { it.first }
        var first = true
        for ((name, original) in keys) {
            if (!first) out.append(',')
            first = false
            writeString(if (name.startsWith("~")) "~$name" else name, out)
            out.append(':')
            writeValue(m[original], out)
        }
        out.append('}')
    }

    private fun writeString(s: String, out: StringBuilder) {
        out.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c < ' ' -> out.append("\\u%04x".format(c.code))
                c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate() -> {
                    out.append(c).append(s[i + 1])
                    i++
                }
                c.isSurrogate() -> out.append("\\u%04x".format(c.code))
                else -> out.append(c)
            }
            i++
        }
        out.append('"')
    }

    // ---- parser ----------------------------------------------------------------------------

    private class ParseFailure : Exception()

    private class Parser(private val s: String) {
        private var i = 0

        fun skipEnd() {
            if (i != s.length) fail()
        }

        private fun fail(): Nothing = throw ParseFailure()

        private fun peek(): Char = if (i < s.length) s[i] else fail()

        private fun expect(c: Char) {
            if (peek() != c) fail()
            i++
        }

        fun value(depth: Int): Any? {
            if (depth > MAX_DEPTH) fail()
            return when (val c = peek()) {
                '{' -> obj(depth)
                '[' -> list(depth)
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c in '0'..'9') number() else fail()
            }
        }

        private fun literal(word: String, v: Any?): Any? {
            if (!s.startsWith(word, i)) fail()
            i += word.length
            return v
        }

        private fun number(): Any {
            val start = i
            if (peek() == '-') i++
            while (i < s.length && (s[i] in '0'..'9' || s[i] in ".eE+-")) i++
            val t = s.substring(start, i)
            return if (t.any { it == '.' || it == 'e' || it == 'E' }) {
                t.toDoubleOrNull() ?: fail()
            } else {
                t.toIntOrNull() ?: t.toLongOrNull() ?: fail()
            }
        }

        private fun list(depth: Int): List<Any?> {
            expect('[')
            val out = ArrayList<Any?>()
            if (peek() == ']') {
                i++
                return out
            }
            while (true) {
                out += value(depth + 1)
                when (peek()) {
                    ',' -> i++
                    ']' -> {
                        i++
                        return out
                    }
                    else -> fail()
                }
            }
        }

        private fun obj(depth: Int): Any? {
            expect('{')
            val out = LinkedHashMap<String, Any?>()
            if (peek() == '}') {
                i++
                return out
            }
            while (true) {
                val k = string()
                expect(':')
                out[k] = value(depth + 1)
                val sep = peek()
                i++
                if (sep == '}') break
                if (sep != ',') fail()
            }
            return untag(out)
        }

        private fun untag(m: LinkedHashMap<String, Any?>): Any? {
            if (m.size == 1) {
                val (k, v) = m.entries.single()
                if (k in TAGS) return tagged(k, v)
            }
            val out = LinkedHashMap<String, Any?>(m.size)
            for ((k, v) in m) {
                if (k.startsWith("~")) {
                    if (!k.startsWith("~~")) fail()
                    out[k.substring(1)] = v
                } else {
                    out[k] = v
                }
            }
            return out
        }

        private fun tagged(tag: String, v: Any?): Any = when (tag) {
            "~L" -> (v as? Int)?.toLong() ?: fail()
            "~D" -> when (v) {
                "NaN" -> Double.NaN
                "Infinity" -> Double.POSITIVE_INFINITY
                "-Infinity" -> Double.NEGATIVE_INFINITY
                else -> fail()
            }
            "~B" -> decodeBase64(v as? String ?: fail())
            else -> (v as? List<*>)?.let { LinkedHashSet(it) } ?: fail()
        }

        private fun decodeBase64(s: String): ByteArray =
            try {
                Base64.getDecoder().decode(s)
            } catch (_: IllegalArgumentException) {
                fail()
            }

        private fun string(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                val c = peek()
                i++
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> sb.append(escape())
                    c < ' ' -> fail()
                    else -> sb.append(c)
                }
            }
        }

        private fun escape(): Char {
            val e = peek()
            i++
            return when (e) {
                '"' -> '"'
                '\\' -> '\\'
                '/' -> '/'
                'n' -> '\n'
                'r' -> '\r'
                't' -> '\t'
                'b' -> '\b'
                'f' -> '\u000c'
                'u' -> {
                    if (i + 4 > s.length) fail()
                    val code = s.substring(i, i + 4).toIntOrNull(16) ?: fail()
                    i += 4
                    code.toChar()
                }
                else -> fail()
            }
        }
    }
}
