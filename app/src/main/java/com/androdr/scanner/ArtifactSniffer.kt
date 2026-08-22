package com.androdr.scanner

import java.io.InputStream
import java.util.zip.ZipInputStream

enum class ArtifactType { BUG_REPORT, INTRUSION_LOG, UNRECOGNIZED }

/**
 * Classifies an imported ZIP by entry names alone (#342 spec §4.1).
 * One decision point in one place (the `when`/branch in [classify]), not a
 * registry framework — this routing point becomes the registry seed if a third
 * artifact type arrives.
 */
object ArtifactSniffer {

    /** Advanced Protection per-day export file, e.g. 2026-08-22.txt. */
    private val intrusionLogEntry = Regex("""\d{4}-\d{2}-\d{2}\.txt""")

    /**
     * Decompressed-byte budget for one sniff (#342 C3, security M5). Classifying
     * a ZIP needs only entry NAMES, but `ZipInputStream` cannot reach the next
     * name without INFLATING the current entry's body — so an unbounded walk
     * fully inflates a deflate bomb here (and the analyzer inflates it again).
     * The sniff stops feeding names once this many decompressed bytes have been
     * read; classification then resolves on the names seen so far. Generous
     * enough that a real bug report (classified on its first `dumpstate` entry)
     * or intrusion-log export (per-day `.txt` files are small) never trips it.
     */
    const val DEFAULT_INFLATE_BUDGET_BYTES: Long = 64L * 1024 * 1024

    private const val DRAIN_BUFFER = 64 * 1024

    /** Outcome of [classifyZip]; [bytesInflated]/[budgetExceeded] exist for tests. */
    data class SniffOutcome(
        val type: ArtifactType,
        val bytesInflated: Long,
        val budgetExceeded: Boolean,
    )

    fun classify(entryNames: Sequence<String>): ArtifactType {
        var sawIntrusionLog = false
        for (name in entryNames) {
            val base = name.substringAfterLast('/').lowercase()
            val isDumpstate = base == "dumpstate.txt" ||
                (base.startsWith("bugreport-") && base.endsWith(".txt"))
            if (isDumpstate) return ArtifactType.BUG_REPORT
            // Top level or one directory deep (covers androidqf's intrusion-logs/).
            if (intrusionLogEntry.matches(base) && name.count { it == '/' } <= 1) {
                sawIntrusionLog = true
            }
        }
        return if (sawIntrusionLog) ArtifactType.INTRUSION_LOG else ArtifactType.UNRECOGNIZED
    }

    /**
     * Reads entry names from [input] as a ZIP and classifies it, INFLATING no
     * more than [budgetBytes] decompressed bytes in the process (#342 C3). The
     * name sequence is lazy: [classify] short-circuits on the first `dumpstate`
     * entry, so a well-formed bug report is classified without draining bodies at
     * all. To advance past an undecided entry the sniff drains it in bounded
     * chunks, counting decompressed bytes; once the budget is exceeded (or an
     * entry's data is corrupt) it stops yielding names and lets [classify] decide
     * on what it has seen — so a bomb cannot force unbounded inflation here.
     * The wrapping ZipInputStream is closed on exit (releasing its Inflater),
     * which also closes [input].
     */
    @Suppress("TooGenericExceptionCaught", "NestedBlockDepth")
    fun classifyZip(
        input: InputStream,
        budgetBytes: Long = DEFAULT_INFLATE_BUDGET_BYTES,
    ): SniffOutcome {
        var inflated = 0L
        var budgetExceeded = false
        val buf = ByteArray(DRAIN_BUFFER)
        ZipInputStream(input.buffered()).use { zip ->
            val names = sequence {
                var entry = try { zip.nextEntry } catch (_: Exception) { null }
                outer@ while (entry != null) {
                    if (!entry.isDirectory) yield(entry.name)
                    // Drain THIS entry ourselves, bounded, so reaching the next name
                    // cannot inflate a bomb without limit. Do NOT call closeEntry() /
                    // nextEntry() past the budget: both inflate the remainder.
                    try {
                        var n = zip.read(buf)
                        while (n >= 0) {
                            inflated += n
                            if (inflated > budgetBytes) { budgetExceeded = true; break@outer }
                            n = zip.read(buf)
                        }
                    } catch (_: Exception) {
                        break@outer // corrupt entry data: classify on names seen so far
                    }
                    entry = try { zip.nextEntry } catch (_: Exception) { null }
                }
            }
            val type = classify(names)
            return SniffOutcome(type, inflated, budgetExceeded)
        }
    }
}
