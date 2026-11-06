package com.androdr.privacy.model

/** Exodus tracker categories; any label the app does not know maps to [OTHER]. */
enum class TrackerCategory(val label: String) {
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
