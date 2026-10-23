package com.androdr.reporting

import com.androdr.data.model.scanWith
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * R3 (spec §7): device-controlled strings, field keys, and values nested in lists and maps are
 * escaped -- `\` and every character in Cc, Cf, Zl, Zp, Co, Cn and Cs becomes `\uXXXX` -- so no
 * value can emit a raw line break, a bidi override, or an ambiguous escape.
 */
class ReportEscapingTest {

    /** Each case: the raw text and its escaped form. */
    private val cases = listOf(
        "\n" to "\\u000A",
        "\r" to "\\u000D",
        "\u2028" to "\\u2028",
        "\u202E" to "\\u202E",
        "\\" to "\\u005C",
        "\uD800" to "\\uD800",
    )

    private val scan = scanWith(
        id = 7L, timestamp = 1_711_900_800_000L, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0,
    )

    @Test
    fun `escapeForReport escapes each case and leaves ordinary text alone`() {
        cases.forEach { (raw, escaped) ->
            assertEquals(escaped, escapeForReport("a${raw}b").removeSurrounding("a", "b"))
        }
        assertEquals("plain ASCII: com.example/1.0 (ok)", escapeForReport("plain ASCII: com.example/1.0 (ok)"))
        // A valid surrogate pair (an assigned emoji) is not a lone surrogate.
        assertEquals("\uD83D\uDE00", escapeForReport("\uD83D\uDE00"))
        // A low surrogate with no high surrogate before it is lone too.
        assertEquals("x\\uDC00", escapeForReport("x\uDC00"))
        // Private use (Co) and a format character (Cf, zero-width joiner).
        assertEquals("\\uE000\\u200D", escapeForReport("\uE000\u200D"))
    }

    @Test
    fun `every case is escaped in a field key and in a field value`() {
        cases.forEachIndexed { i, (raw, escaped) ->
            val text = reportText(scan, telemetry = FakeTelemetry(mapOf("app_scanner" to listOf(
                mapOf("k${raw}ey$i" to "v${raw}al$i"),
            ))))
            assertTrue("case $i key: $text", text.contains("k${escaped}ey$i"))
            assertTrue("case $i value: $text", text.contains("v${escaped}al$i"))
            assertFalse("case $i raw key", text.contains("k${raw}ey$i"))
            assertFalse("case $i raw value", text.contains("v${raw}al$i"))
        }
    }

    @Test
    fun `every case is escaped inside a list element of a map value, and in a nested map key`() {
        cases.forEachIndexed { i, (raw, escaped) ->
            val text = reportText(scan, telemetry = FakeTelemetry(mapOf("device_auditor" to listOf(
                mapOf(
                    "unpatched_cves" to listOf(mapOf("cve_id" to "CVE-$i${raw}x")),
                    "nested" to mapOf("in${raw}ner$i" to listOf("a${raw}b$i")),
                ),
            ))))
            assertTrue("case $i list-of-maps value: $text", text.contains("CVE-$i${escaped}x"))
            assertTrue("case $i nested key: $text", text.contains("in${escaped}ner$i"))
            assertTrue("case $i list element: $text", text.contains("a${escaped}b$i"))
            assertFalse(text.contains("CVE-$i${raw}x"))
            assertFalse(text.contains("in${raw}ner$i"))
            assertFalse(text.contains("a${raw}b$i"))
        }
    }

    @Test
    fun `a device-controlled string in the findings section cannot break a line or reverse text`() {
        val f = Finding(
            ruleId = "androdr-001", title = "Sideloaded app", level = "high", category = FindingCategory.APP_RISK,
            triggered = true,
            matchContext = mapOf("package_name" to "com.evil\nFlags   : forged", "app_name" to "Innocent\u202Eexe.gpj"),
        )
        val text = reportText(scan.copy(findings = listOf(f)), mode = ExportMode.FINDINGS_ONLY)
        assertTrue(text, text.contains("com.evil\\u000AFlags   : forged"))
        assertTrue(text, text.contains("Innocent\\u202Eexe.gpj"))
        assertFalse(text.lines().any { it.trimStart().startsWith("Flags   : forged") })
        assertFalse(text.contains("\u202E"))
    }
}
