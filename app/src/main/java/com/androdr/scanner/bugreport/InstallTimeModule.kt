package com.androdr.scanner.bugreport

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.PackageHistoryEventType
import com.androdr.data.model.PackageInstallHistoryEntry
import com.androdr.data.model.TelemetrySource
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
    private val lastUpdateRegex = Regex("""lastUpdateTime=([\d\- :]+)""")

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

    private val versionCodeRegex = Regex("""versionCode=(\d+)""")

    private data class ParsedPackage(
        val name: String,
        val firstInstallMs: Long,
        val lastUpdateMs: Long?,
        val versionCode: Long?,
    )

    fun parseSection(text: String): List<ForensicTimelineEvent> = parsePackages(text).map {
        ForensicTimelineEvent(
            startTimestamp = it.firstInstallMs,
            kind = "event",
            category = "package_install",
            source = "bugreport",
            description = "Package installed: ${it.name}",
            packageName = it.name,
            appName = it.name,
            telemetrySource = TelemetrySource.BUGREPORT_IMPORT
        )
    }

    /**
     * The typed install-history records for the same packages [parseSection] turns into rows:
     * an INSTALL per `firstInstallTime`, plus an UPDATE per parsed `lastUpdateTime` that differs
     * from `firstInstallTime` (equal values are the same instant, so no update happened).
     */
    fun parseHistory(text: String, capturedAt: Long): List<PackageInstallHistoryEntry> =
        parsePackages(text).flatMap { p ->
            fun entry(type: PackageHistoryEventType, ts: Long) = PackageInstallHistoryEntry(
                packageName = p.name,
                eventType = type,
                timestamp = ts,
                versionCode = p.versionCode,
                source = TelemetrySource.BUGREPORT_IMPORT,
                capturedAt = capturedAt,
            )
            listOfNotNull(
                entry(PackageHistoryEventType.INSTALL, p.firstInstallMs),
                p.lastUpdateMs?.takeIf { it != p.firstInstallMs }
                    ?.let { entry(PackageHistoryEventType.UPDATE, it) },
            )
        }

    private fun parseTime(regex: Regex, block: String, label: String): Long? =
        regex.find(block)?.groupValues?.get(1)?.trim()?.let { raw ->
            runCatching {
                LocalDateTime.parse(raw, dateFormatter).toInstant(ZoneOffset.UTC).toEpochMilli()
            }.getOrElse {
                android.util.Log.w("InstallTimeModule", "Failed to parse $label='$raw'", it)
                null
            }
        }

    private fun parsePackages(text: String): List<ParsedPackage> {
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

            val firstInstallMs = parseTime(firstInstallRegex, packageBlock, "firstInstallTime")
                ?: return@mapIndexedNotNull null
            val lastUpdateMs = parseTime(lastUpdateRegex, packageBlock, "lastUpdateTime")

            val versionCode = versionCodeRegex.find(packageBlock)?.groupValues?.get(1)?.toLongOrNull()
            ParsedPackage(pkg, firstInstallMs, lastUpdateMs, versionCode)
        }
    }
}
