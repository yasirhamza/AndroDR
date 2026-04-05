package com.androdr.reporting

/**
 * Shared utility for computing action guidance priority from rule-authored
 * guidance strings. Used by both ReportFormatter and TimelineExporter to
 * determine assessment severity from the guidance field.
 */
object GuidanceUtils {

    /**
     * Returns a priority score for a guidance string based on its prefix.
     * Higher = more severe. Used for sorting and assessment thresholds.
     *
     * Thresholds: >= 3 → CRITICAL assessment, >= 1 → REVIEW, 0 → no action
     */
    fun guidancePriority(guidance: String): Int {
        val upper = guidance.uppercase()
        return when {
            upper.startsWith("CRITICAL") -> 4
            upper.startsWith("UNINSTALL IMMEDIATELY") -> 3
            upper.startsWith("UNINSTALL") -> 2
            upper.startsWith("INVESTIGATE") -> 1
            upper.startsWith("REVIEW") -> 1
            else -> 0
        }
    }
}
