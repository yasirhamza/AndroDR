package com.androdr.scanner

enum class ArtifactType { BUG_REPORT, INTRUSION_LOG, UNRECOGNIZED }

/**
 * Classifies an imported ZIP by entry names alone (#342 spec §4.1).
 * Deliberately one `when` in one place, not a registry framework — this
 * routing point becomes the registry seed if a third artifact type arrives.
 */
object ArtifactSniffer {

    /** Advanced Protection per-day export file, e.g. 2026-08-22.txt. */
    private val intrusionLogEntry = Regex("""\d{4}-\d{2}-\d{2}\.txt""")

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
}
