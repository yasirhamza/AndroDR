package com.androdr.scanner.bugreport

import com.androdr.data.model.ForensicTimelineEvent
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/**
 * Parses the `package` section of a bug report (`dumpsys package`) to emit
 * `package_install` ForensicTimelineEvent rows — the bug-report analog of the
 * runtime [com.androdr.scanner.InstallEventEmitter]. Handles missing timestamps
 * gracefully: a package without a parseable `firstInstallTime` produces no event.
 *
 * Unlike the runtime path, no delta detection is performed — bug reports are
 * point-in-time snapshots, and we want every install row that's in there so the
 * forensic timeline reflects the full package inventory captured at report time.
 *
 * Note: timestamps in `dumpsys package` are formatted as `yyyy-MM-dd HH:mm:ss`
 * in the device's local time zone. We parse with [TimeZone.getDefault], which
 * is correct when the analyzing device shares the capturing device's time zone;
 * cross-zone analysis may shift values by the offset difference.
 */
class InstallTimeModule {

    private val packageHeaderRegex = Regex("""^Package \[([^\]]+)\]""", RegexOption.MULTILINE)
    private val firstInstallRegex = Regex("""firstInstallTime=([\d\- :]+)""")

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).apply {
        timeZone = TimeZone.getDefault()
    }

    fun parseSection(text: String): List<ForensicTimelineEvent> {
        val packageStarts = packageHeaderRegex.findAll(text).toList()
        if (packageStarts.isEmpty()) return emptyList()

        return packageStarts.mapIndexedNotNull { idx, match ->
            val pkg = match.groupValues[1]
            val sectionEnd = if (idx + 1 < packageStarts.size) {
                packageStarts[idx + 1].range.first
            } else {
                text.length
            }
            val packageBlock = text.substring(match.range.first, sectionEnd)

            val firstInstallMs = firstInstallRegex.find(packageBlock)
                ?.groupValues?.get(1)?.trim()
                ?.let { runCatching { dateFormat.parse(it)?.time }.getOrNull() }
                ?: return@mapIndexedNotNull null

            ForensicTimelineEvent(
                startTimestamp = firstInstallMs,
                kind = "event",
                category = "package_install",
                source = "bugreport",
                description = "Package installed: $pkg",
                severity = "info",
                packageName = pkg,
                appName = pkg,
                isFromBugreport = true
            )
        }
    }
}
