package com.androdr.privacy.model

/**
 * Tracker categories: Exodus's, plus [PROXYWARE], which is AndroDR's own (entries from the rules
 * repository's `validation/tracker-supplement.yml`). Any label the app does not know maps to
 * [OTHER]. The order is the order of the threshold sheet.
 */
enum class TrackerCategory(val label: String) {
    PROXYWARE("Proxyware"),
    ADVERTISEMENT("Advertisement"),
    PROFILING("Profiling"),
    IDENTIFICATION("Identification"),
    LOCATION("Location"),
    ANALYTICS("Analytics"),
    CRASH_REPORTING("Crash reporting"),
    UNCATEGORISED("Uncategorised"),
    OTHER("Other");

    companion object {
        fun fromLabel(label: String): TrackerCategory = entries.firstOrNull { it.label == label } ?: OTHER
    }
}
