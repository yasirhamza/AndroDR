package com.androdr.util

/** Longest an untrusted name (app label, tracker name) may be on screen, in code points. */
const val MAX_DISPLAY_NAME_CHARS = 80

/**
 * Makes an untrusted name (an app's label, a registry tracker name) safe to show on screen, keeping every
 * script's letters, digits and punctuation ("Résumé" stays "Résumé", Arabic stays Arabic).
 *
 * Removed: ISO control characters (CR/LF/tab become a space, so a label cannot add lines), all format
 * characters (Unicode type Cf, which includes the bidi embeddings, overrides and isolates U+202A–U+202E and
 * U+2066–U+2069, the marks U+200E, U+200F and U+061C, and zero-width characters) and lone surrogates.
 * Whitespace runs collapse to one space, the result is trimmed and
 * capped at [max] code points (never splitting a surrogate pair).
 *
 * This is for the screen only. Reports stay printable ASCII through [reportSafe].
 */
fun displaySafe(value: String, max: Int = MAX_DISPLAY_NAME_CHARS): String {
    val out = StringBuilder()
    var pendingSpace = false
    var count = 0
    var i = 0
    while (i < value.length && count < max) {
        val cp = value.codePointAt(i)
        i += Character.charCount(cp)
        when {
            Character.isISOControl(cp) || Character.isWhitespace(cp) || Character.isSpaceChar(cp) ->
                pendingSpace = out.isNotEmpty()
            Character.getType(cp).toByte() in DROPPED_TYPES -> Unit
            else -> {
                if (pendingSpace) {
                    out.append(' ')
                    count++
                    pendingSpace = false
                    if (count >= max) break
                }
                out.appendCodePoint(cp)
                count++
            }
        }
    }
    return out.toString().trimEnd()
}

private val DROPPED_TYPES = setOf(Character.FORMAT, Character.SURROGATE, Character.CONTROL)
