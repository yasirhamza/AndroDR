package com.androdr.ui.history

import androidx.annotation.StringRes
import com.androdr.R
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.reporting.groupedCount

// Pure text choices of the History screen, kept apart from its composables.

/**
 * The note shown in place of the "since previous scan" diff, or null when the diff is shown. An import
 * is evidence from another time or device and is never compared (ruling R44), so it does not claim to
 * be a first scan.
 */
@StringRes
internal fun diffNote(source: TelemetrySource, isFirstScan: Boolean, hasDiff: Boolean): Int? = when {
    source != TelemetrySource.LIVE_SCAN -> R.string.history_import_not_compared
    isFirstScan || !hasDiff -> R.string.first_scan_no_comparison
    else -> null
}

/** A History row's counts, each with the locale's digit grouping (battery B4). */
internal fun scanCountLines(scan: ScanResult): String = buildString {
    append("\u2022 ${groupedCount(scan.triggeredCount.toLong())} finding(s) triggered\n")
    append("\u2022 ${groupedCount(scan.knownMalwareCount.toLong())} known malware app(s)\n")
    append("\u2022 ${groupedCount(scan.riskySideloadCount.toLong())} sideloaded app(s)")
}
