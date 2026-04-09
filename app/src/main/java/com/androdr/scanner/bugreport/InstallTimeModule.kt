package com.androdr.scanner.bugreport

import com.androdr.data.model.ForensicTimelineEvent
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale

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

    // DateTimeFormatter is immutable and thread-safe; SimpleDateFormat is not.
    // Timestamps are interpreted as UTC for determinism: bug reports do not
    // carry a zone offset on dumpsys timestamps, and parsing them in the
    // analyzing device's local zone made cross-zone analyses non-reproducible.
    // The trade-off is a fixed offset error bounded by ±12h that is the same
    // for every analyzer of the same report. A future task should plumb the
    // device timezone from `SYSTEM PROPERTIES` (persist.sys.timezone) into
    // this module for an exact fix.
    private val dateFormatter: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.US)

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
                ?.let { raw ->
                    runCatching {
                        LocalDateTime.parse(raw, dateFormatter).toInstant(ZoneOffset.UTC).toEpochMilli()
                    }.getOrElse {
                        android.util.Log.w("InstallTimeModule", "Failed to parse firstInstallTime='$raw'", it)
                        null
                    }
                }
                ?: return@mapIndexedNotNull null

            ForensicTimelineEvent(
                startTimestamp = firstInstallMs,
                kind = "event",
                category = "package_install",
                source = "bugreport",
                description = "Package installed: $pkg",
                packageName = pkg,
                appName = pkg,
                telemetrySource = com.androdr.data.model.TelemetrySource.BUGREPORT_IMPORT
            )
        }
    }
}
