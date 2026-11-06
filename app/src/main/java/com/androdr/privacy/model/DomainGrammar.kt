package com.androdr.privacy.model

import java.util.Locale
import java.util.regex.Pattern
import java.util.regex.PatternSyntaxException

/**
 * Restricted domain-pattern grammar. A line-for-line port of
 * `validation/domain_grammar.py` in the rules repo; both read the same fixture
 * file (`domain_grammar_fixtures.txt`), so they cannot drift apart.
 *
 * A pattern is a sequence of atoms, each optionally followed by one of * + ?.
 * An atom is a lower-case letter, digit or '-', an escaped \. or \-, a bare '.',
 * or a non-empty class [...] whose items are a single [a-z0-9], exactly a-z,
 * exactly 0-9, or a literal '-' in first or last position. The tokenizer is
 * hand-written and rejects everything else, so no accepted pattern can backtrack
 * catastrophically.
 */
@Suppress("ReturnCount")
object DomainGrammar {
    const val MAX_PATTERNS_PER_TRACKER = 4
    const val MAX_PATTERNS_TOTAL = 64
    private const val MAX_PATTERN_LENGTH = 200
    private const val MAX_QUANTIFIERS = 2
    private const val CLASS_RANGE_LEN = 3

    private const val LITERAL = "abcdefghijklmnopqrstuvwxyz0123456789-"
    private const val QUANTIFIERS = "*+?"

    private val PREFIX = Regex("[a-z0-9_]+(\\.[A-Za-z0-9_]+)+")
    private val SEGMENT = Regex("[a-z0-9_]+")
    private val SUFFIX = Regex("[a-z0-9-]+(\\.[a-z0-9-]+)+")
    private val LABEL = Regex("[a-z0-9-]+")

    // ASCII-only on purpose: kotlin.text.Regex(IGNORE_CASE) adds UNICODE_CASE, under which [a-z]
    // also matches U+212A KELVIN SIGN and U+017F LONG S. java.util.regex with only CASE_INSENSITIVE
    // is ASCII-only; \S and \d are ASCII by default. The host class has no '@' (no userinfo);
    // an '@' in the path is allowed.
    private val WEBSITE: Pattern =
        Pattern.compile("https?://[a-z0-9.-]+(:\\d+)?(/\\S*)?", Pattern.CASE_INSENSITIVE)

    /** The regex text for a class body, or null when it is not allowed. */
    private fun tokenizeClass(body: String): String? {
        if (body.isEmpty()) return null
        val out = StringBuilder()
        var i = 0
        val n = body.length
        while (i < n) {
            val c = body[i]
            if (c == '-') {
                if (i != 0 && i != n - 1) return null
                out.append("\\-")
                i += 1
            } else if (c in LITERAL) {
                if (i + 1 < n && body[i + 1] == '-' && i + 2 < n) {
                    val range = body.substring(i, i + CLASS_RANGE_LEN)
                    if (range != "a-z" && range != "0-9") return null
                    out.append(range)
                    i += CLASS_RANGE_LEN
                } else {
                    out.append(c)
                    i += 1
                }
            } else {
                return null
            }
        }
        return "[$out]"
    }

    /** A list of (regex_text, quantifier) atoms, or null when rejected. */
    @Suppress("CyclomaticComplexMethod")
    private fun tokenize(p: String): List<Pair<String, String>>? {
        val atoms = ArrayList<Pair<String, String>>()
        var i = 0
        val n = p.length
        while (i < n) {
            val c = p[i]
            val text: String
            if (c == '\\') {
                if (i + 1 < n && p[i + 1] in ".-") {
                    text = if (p[i + 1] == '.') "\\." else "\\-"
                    i += 2
                } else {
                    return null
                }
            } else if (c == '[') {
                val end = p.indexOf(']', i + 1)
                if (end < 0) return null
                text = tokenizeClass(p.substring(i + 1, end)) ?: return null
                i = end + 1
            } else if (c == '.') {
                text = "."
                i += 1
            } else if (c in LITERAL) {
                text = c.toString()
                i += 1
            } else {
                return null
            }
            var quant = ""
            if (i < n && p[i] in QUANTIFIERS) {
                quant = p[i].toString()
                i += 1
            }
            atoms.add(text to quant)
        }
        return atoms
    }

    /** Compiles a restricted pattern, or returns null when it is not accepted. */
    fun compilePattern(p: String): Regex? {
        if (p.isEmpty() || p.length > MAX_PATTERN_LENGTH) return null
        val atoms = tokenize(p)
        if (atoms.isNullOrEmpty()) return null
        if (atoms.count { it.second.isNotEmpty() } > MAX_QUANTIFIERS) return null
        if (atoms.all { it.second == "*" || it.second == "?" }) return null // would match the empty string
        return try {
            Regex(atoms.joinToString("") { it.first + it.second })
        } catch (_: PatternSyntaxException) {
            null
        }
    }

    fun isRestrictedPattern(p: String): Boolean = compilePattern(p) != null

    private fun isWebsite(s: String): Boolean = s.isEmpty() || WEBSITE.matcher(s).matches()

    val FIELD_CHECKS: Map<String, (String) -> Boolean> = mapOf(
        "website" to ::isWebsite,
        "prefix" to { s -> PREFIX.matches(s) },
        "segment" to { s -> SEGMENT.matches(s) },
        "suffix" to { s -> SUFFIX.matches(s) },
        "label" to { s -> LABEL.matches(s) },
        "pattern" to ::isRestrictedPattern,
    )

    /** The single definition of suffix / label / pattern matching against a host. */
    fun matchesHost(kind: String, value: String, host: String): Boolean {
        val h = host.lowercase(Locale.ROOT)
        val labels = h.split(".")
        return when (kind) {
            "suffix" -> h == value || h.endsWith(".$value")
            "label" -> value in labels
            "pattern" -> {
                val rx = compilePattern(value) ?: return false
                labels.indices.any { rx.matches(labels.subList(it, labels.size).joinToString(".")) }
            }
            else -> throw IllegalArgumentException("unknown kind: $kind")
        }
    }
}
