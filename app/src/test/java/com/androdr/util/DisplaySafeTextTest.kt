package com.androdr.util

import org.junit.Assert.assertEquals
import org.junit.Test

class DisplaySafeTextTest {

    @Test fun `letters of every script are kept`() {
        assertEquals("Résumé", displaySafe("Résumé"))
        assertEquals("تطبيق", displaySafe("تطبيق"))
        assertEquals("追踪 SDK", displaySafe("追踪 SDK"))
        assertEquals("Ünïcødé-1.2 (beta)!", displaySafe("Ünïcødé-1.2 (beta)!"))
    }

    @Test fun `every bidi control is removed`() {
        val bidi = listOf(
            0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C,
        )
        for (cp in bidi) {
            val s = "a" + String(Character.toChars(cp)) + "b"
            assertEquals("U+%04X".format(cp), "ab", displaySafe(s))
        }
    }

    @Test fun `controls become spaces, whitespace collapses and the result is trimmed`() {
        assertEquals("a b c", displaySafe(" \ta\r\n\nb\u0000  c  "))
        assertEquals("", displaySafe("\u0001‮​\n"))
    }

    @Test fun `the cap counts code points and never splits a surrogate pair`() {
        assertEquals(80, displaySafe("x".repeat(200)).length)
        val emoji = "😀" // one code point, two chars
        val capped = displaySafe(emoji.repeat(100), max = 3)
        assertEquals(emoji.repeat(3), capped)
        assertEquals("", displaySafe("\uD83D")) // a lone surrogate is dropped
    }
}
