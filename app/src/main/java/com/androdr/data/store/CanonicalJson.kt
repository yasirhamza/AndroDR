package com.androdr.data.store

import java.math.BigDecimal
import java.math.MathContext
import java.math.RoundingMode
import java.util.Base64
import kotlin.math.abs

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
    private const val MIN_DIGITS = 2
    private const val MAX_DIGITS = 17
    private const val PLAIN_MIN = 1e-3
    private const val PLAIN_MAX = 1e7

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
        val special = when {
            d.isNaN() -> "NaN"
            d == Double.POSITIVE_INFINITY -> "Infinity"
            d == Double.NEGATIVE_INFINITY -> "-Infinity"
            else -> null
        }
        if (special != null) out.append("{\"~D\":\"").append(special).append("\"}") else out.append(formatDouble(d))
    }

    /**
     * A finite [d] as the shortest decimal of at least two significant digits that rounds back to
     * [d] (nearest-even when two are equally short), laid out as `Double.toString` lays it out: plain
     * for 10^-3 <= |d| < 10^7, else `d.dddE±n`. Exact arithmetic only (#418): `Double.toString`
     * differs across Java releases and Android versions, and the canonical bytes are hashed, so the
     * platform's formatter must never decide them. Matches JDK 19+ `Double.toString` (the host JVM
     * is the test reference). Frozen contract: these bytes are part of every stored fact's identity,
     * so a change here re-keys stored doubles; version the encoding instead of editing it.
     */
    internal fun formatDouble(d: Double): String {
        require(!d.isNaN() && !d.isInfinite()) { "not finite: canonical doubles tag NaN and infinities" }
        val negative = d < 0.0 || (d == 0.0 && 1.0 / d < 0.0)
        val a = abs(d)
        if (a == 0.0) return if (negative) "-0.0" else "0.0"
        val digits = shortestDigits(a)
        val unscaled = digits.unscaledValue().toString()
        // Scientific exponent of the first digit: a = d1.d2d3... * 10^exp.
        val exp = unscaled.length - 1 - digits.scale()
        val body = if (a >= PLAIN_MIN && a < PLAIN_MAX) plain(unscaled, exp) else scientific(unscaled, exp)
        return if (negative) "-$body" else body
    }

    /**
     * The shortest decimal in [a]'s (> 0) round-to-nearest interval; of two that short, the closer
     * to [a], then the one with an even last digit.
     */
    private fun shortestDigits(a: Double): BigDecimal {
        val exact = BigDecimal(a)
        val two = BigDecimal.valueOf(2)
        // Halfway points to the neighbouring doubles: a decimal strictly between them reads back as
        // [a], and one exactly on them does when [a]'s significand is even (ties to even). Above a
        // power of two the upper half is twice the lower, so check both p-digit neighbours of [a]
        // (its floor and ceiling): if neither is in the interval, no p-digit decimal is.
        val low = exact.add(BigDecimal(Math.nextDown(a))).divide(two)
        val high = exact.add(BigDecimal(Math.ulp(a)).divide(two))
        val evenSignificand = (java.lang.Double.doubleToRawLongBits(a) and 1L) == 0L
        fun inInterval(r: BigDecimal): Boolean {
            val lo = r.compareTo(low)
            val hi = r.compareTo(high)
            return (lo > 0 && hi < 0) || (evenSignificand && (lo == 0 || hi == 0))
        }
        for (precision in MIN_DIGITS..MAX_DIGITS) {
            val candidates = listOf(RoundingMode.FLOOR, RoundingMode.CEILING)
                .map { exact.round(MathContext(precision, it)) }
                .filter(::inInterval)
            val best = when (candidates.size) {
                0 -> continue
                1 -> candidates[0]
                else -> closer(exact, candidates[0], candidates[1])
            }
            return best.stripTrailingZeros()
        }
        return exact.round(MathContext(MAX_DIGITS, RoundingMode.HALF_EVEN)).stripTrailingZeros()
    }

    /** Of [floor] <= [exact] <= [ceiling], the closer; on a tie, the one whose last digit is even. */
    private fun closer(exact: BigDecimal, floor: BigDecimal, ceiling: BigDecimal): BigDecimal {
        val cmp = exact.subtract(floor).compareTo(ceiling.subtract(exact))
        return when {
            cmp < 0 -> floor
            cmp > 0 -> ceiling
            floor.unscaledValue().testBit(0) -> ceiling
            else -> floor
        }
    }

    private fun plain(digits: String, exp: Int): String = if (exp >= 0) {
        val whole = if (digits.length > exp + 1) digits.substring(0, exp + 1) else digits.padEnd(exp + 1, '0')
        val fraction = if (digits.length > exp + 1) digits.substring(exp + 1) else "0"
        "$whole.$fraction"
    } else {
        "0." + "0".repeat(-exp - 1) + digits
    }

    private fun scientific(digits: String, exp: Int): String =
        digits[0] + "." + (if (digits.length > 1) digits.substring(1) else "0") + "E" + exp

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
