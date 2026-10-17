package com.androdr.ioc

import com.androdr.data.model.Indicator

/** Bounds feed-controlled strings before they reach the DB, reports and UI (spec §3.1a, R13). */
object IocSanitizer {
    internal val CATEGORIES = setOf("STALKERWARE", "SPYWARE", "MALWARE", "NATION_STATE_SPYWARE",
        "FORENSIC_TOOL", "MONITORING", "DATA_BROKER_SDK")
    private val KEY = Regex("^[a-z0-9_-]{1,32}$")
    private const val MAX_FAMILY = 120
    private const val MAX_REFERENCE = 512
    private const val MAX_DESCRIPTION = 1000

    private val STRIP = setOf(Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.LINE_SEPARATOR.toInt(),
        Character.PARAGRAPH_SEPARATOR.toInt(), Character.SURROGATE.toInt(), Character.PRIVATE_USE.toInt())

    /** Drops control, bidi/zero-width (FORMAT), line/paragraph separators, lone surrogates. */
    fun clean(s: String): String = buildString {
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            if (Character.getType(cp) !in STRIP) appendCodePoint(cp)
            i += Character.charCount(cp)
        }
    }.trim()

    /** Truncate by code point, never splitting a surrogate pair. */
    private fun String.takeCodePoints(n: Int): String =
        if (codePointCount(0, length) <= n) this else substring(0, offsetByCodePoints(0, n))

    fun sanitize(i: Indicator): Indicator = i.copy(
        family = clean(i.family).takeCodePoints(MAX_FAMILY),
        category = clean(i.category).takeIf { it in CATEGORIES }.orEmpty(),
        campaignKey = clean(i.campaignKey).takeIf { KEY.matches(it) }.orEmpty(),
        reference = clean(i.reference).takeIf {
            it.length <= MAX_REFERENCE && (it.startsWith("https://") || it.startsWith("feed:"))
        }.orEmpty(),
        description = clean(i.description).takeCodePoints(MAX_DESCRIPTION),
    )
}
