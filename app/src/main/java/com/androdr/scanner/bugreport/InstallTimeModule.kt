package com.androdr.scanner.bugreport

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.PackageHistoryEventType
import com.androdr.data.model.PackageInstallHistoryEntry
import com.androdr.data.model.TelemetrySource
import java.time.LocalDateTime
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
 * Timestamps in `dumpsys package` are `yyyy-MM-dd HH:mm:ss` on the capture device's wall
 * clock, with no offset. They are read with the import's [DumpsysClock] (ruling R27): the zone
 * the report names in `persist.sys.timezone`, or UTC flagged as an assumption. Never the
 * analyzing device's zone, so every analyzer of one report gets the same instants.
 */
class InstallTimeModule {

    private val packageHeaderRegex = Regex("""^Package \[([^\]]+)\]""", RegexOption.MULTILINE)
    private val firstInstallRegex = Regex("""firstInstallTime=([\d\- :]+)""")
    private val lastUpdateRegex = Regex("""lastUpdateTime=([\d\- :]+)""")

    // DateTimeFormatter is immutable and thread-safe; SimpleDateFormat is not.
    private val dateFormatter: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.US)

    private val versionCodeRegex = Regex("""versionCode=(\d+)""")

    private data class ParsedPackage(
        val name: String,
        val firstInstallMs: Long,
        val lastUpdateMs: Long?,
        val versionCode: Long?,
    )

    fun parseSection(text: String, clock: DumpsysClock = DumpsysClock.ASSUMED_UTC): List<ForensicTimelineEvent> =
        parsePackages(text, clock).map {
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
    fun parseHistory(
        text: String,
        capturedAt: Long,
        clock: DumpsysClock = DumpsysClock.ASSUMED_UTC,
    ): List<PackageInstallHistoryEntry> =
        parsePackages(text, clock).flatMap { p ->
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

    private fun parseTime(regex: Regex, block: String, label: String, clock: DumpsysClock): Long? =
        regex.find(block)?.groupValues?.get(1)?.trim()?.let { raw ->
            runCatching {
                clock.epochMs(LocalDateTime.parse(raw, dateFormatter))
            }.getOrElse {
                android.util.Log.w("InstallTimeModule", "Failed to parse $label='$raw'", it)
                null
            }
        }

    private fun parsePackages(text: String, clock: DumpsysClock): List<ParsedPackage> {
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

            val firstInstallMs = parseTime(firstInstallRegex, packageBlock, "firstInstallTime", clock)
                ?: return@mapIndexedNotNull null
            val lastUpdateMs = parseTime(lastUpdateRegex, packageBlock, "lastUpdateTime", clock)

            val versionCode = versionCodeRegex.find(packageBlock)?.groupValues?.get(1)?.toLongOrNull()
            ParsedPackage(pkg, firstInstallMs, lastUpdateMs, versionCode)
        }
    }
}
