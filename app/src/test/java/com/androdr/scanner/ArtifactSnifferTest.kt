package com.androdr.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ArtifactSnifferTest {

    /** Builds an in-memory ZIP; entries are (name, uncompressed-body). */
    private fun zipOf(vararg entries: Pair<String, ByteArray>): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { zos ->
            for ((name, body) in entries) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(body)
                zos.closeEntry()
            }
        }
        return bos.toByteArray()
    }

    // ── C3 (security M5): bounded decompression during the sniff ──────────

    @Test
    fun `sniff caps decompression on an oversized entry`() {
        // 5 MB of zeros compresses tiny but inflates to 5 MB. An unbounded walk
        // would inflate all of it just to reach the next name; the budget must
        // stop it far short.
        val budget = 64L * 1024
        val zip = zipOf("junk.bin" to ByteArray(5_000_000))
        val outcome = ArtifactSniffer.classifyZip(ByteArrayInputStream(zip), budgetBytes = budget)

        assertTrue("budget must be reported exceeded", outcome.budgetExceeded)
        assertTrue(
            "inflated ${outcome.bytesInflated} bytes — not bounded by the budget",
            outcome.bytesInflated <= budget + 128 * 1024,
        )
        assertEquals(ArtifactType.UNRECOGNIZED, outcome.type)
    }

    @Test
    fun `bug report is classified without inflating any body`() {
        // dumpstate.txt is the first entry, so classify short-circuits before
        // draining anything — even a huge trailing entry is never inflated.
        val zip = zipOf(
            "dumpstate.txt" to "boot".toByteArray(),
            "big.bin" to ByteArray(5_000_000),
        )
        val outcome = ArtifactSniffer.classifyZip(ByteArrayInputStream(zip))

        assertEquals(ArtifactType.BUG_REPORT, outcome.type)
        assertEquals("no body should be inflated for an early bug-report match", 0L, outcome.bytesInflated)
        assertTrue(!outcome.budgetExceeded)
    }

    @Test
    fun `well-formed intrusion log classifies within budget`() {
        val zip = zipOf(
            "2026-08-20.txt" to "a".repeat(100).toByteArray(),
            "2026-08-21.txt" to "b".repeat(100).toByteArray(),
            "2026-08-22.txt" to "c".repeat(100).toByteArray(),
        )
        val outcome = ArtifactSniffer.classifyZip(ByteArrayInputStream(zip))

        assertEquals(ArtifactType.INTRUSION_LOG, outcome.type)
        assertTrue("legit export must not trip the budget", !outcome.budgetExceeded)
        assertTrue(outcome.bytesInflated < ArtifactSniffer.DEFAULT_INFLATE_BUDGET_BYTES)
    }

    @Test
    fun `dumpstate entry wins as bug report`() {
        assertEquals(
            ArtifactType.BUG_REPORT,
            ArtifactSniffer.classify(sequenceOf("dumpstate.txt", "2026-08-22.txt"))
        )
    }

    @Test
    fun `bugreport-prefixed txt is a bug report`() {
        assertEquals(
            ArtifactType.BUG_REPORT,
            ArtifactSniffer.classify(sequenceOf("bugreport-crownqltesq-2026-08-22.txt"))
        )
    }

    @Test
    fun `per-day txt at top level is an intrusion log`() {
        assertEquals(
            ArtifactType.INTRUSION_LOG,
            ArtifactSniffer.classify(sequenceOf("2026-08-22.txt"))
        )
    }

    @Test
    fun `per-day txt one directory deep matches (androidqf layout)`() {
        assertEquals(
            ArtifactType.INTRUSION_LOG,
            ArtifactSniffer.classify(sequenceOf("intrusion-logs/2026-08-21.txt"))
        )
    }

    @Test
    fun `per-day txt nested deeper does not match`() {
        assertEquals(
            ArtifactType.UNRECOGNIZED,
            ArtifactSniffer.classify(sequenceOf("a/b/2026-08-21.txt"))
        )
    }

    // ── #356: "(N)" continuation chunks ───────────────────────────────────
    //
    // The exporter rolls a day over into 2026-08-22(1).txt, (2)… every 8,192
    // lines. The old exact-basename regex skipped every chunk — ~47% of the real
    // Z Fold8 export — and a ZIP whose only entries are chunks classified as
    // UNRECOGNIZED, so the import was refused outright.

    @Test
    fun `a zip containing only a continuation chunk is an intrusion log`() {
        val zip = zipOf("2026-08-22(1).txt" to "x".repeat(100).toByteArray())
        val outcome = ArtifactSniffer.classifyZip(ByteArrayInputStream(zip))

        assertEquals(ArtifactType.INTRUSION_LOG, outcome.type)
    }

    @Test
    fun `continuation chunk names match the shared per-day predicate`() {
        assertTrue(ArtifactSniffer.isPerDayLogEntry("2026-08-22.txt"))
        assertTrue(ArtifactSniffer.isPerDayLogEntry("2026-08-22(1).txt"))
        assertTrue(ArtifactSniffer.isPerDayLogEntry("2026-08-23(10).txt"))
        assertTrue("case-insensitive", ArtifactSniffer.isPerDayLogEntry("2026-08-22(2).TXT"))
        assertTrue("one directory deep", ArtifactSniffer.isPerDayLogEntry("intrusion-logs/2026-08-22(1).txt"))
    }

    @Test
    fun `the shared per-day predicate rejects lookalike names`() {
        assertFalse(ArtifactSniffer.isPerDayLogEntry("2026-08-22x.txt"))
        assertFalse(ArtifactSniffer.isPerDayLogEntry("foo(1).txt"))
        assertFalse(ArtifactSniffer.isPerDayLogEntry("2026-08-22().txt"))
        assertFalse(ArtifactSniffer.isPerDayLogEntry("2026-08-22(1).txt.bak"))
        assertFalse("nested deeper than one directory", ArtifactSniffer.isPerDayLogEntry("a/b/2026-08-22(1).txt"))
    }

    @Test
    fun `random zip is unrecognized`() {
        assertEquals(
            ArtifactType.UNRECOGNIZED,
            ArtifactSniffer.classify(sequenceOf("photo.jpg", "notes.txt"))
        )
    }
}
