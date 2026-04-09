package com.androdr.scanner.bugreport

import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.WakelockAcquisition
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses wakelock acquisitions from a bugreport's `dumpsys power` section.
 * Used by plan 6's `sigma_androdr_persistent_wakelock.yml` rule to detect
 * always-on surveillance behavior — though the rule ships disabled pending
 * UAT threshold calibration (#87).
 *
 * Format (typical `dumpsys power`):
 *   Wake Locks: size=3
 *     PARTIAL_WAKE_LOCK   'tag'   ACQ=-2h15m30s TAG=com.example (uid=10123)
 *
 * The `ACQ=-Xh Ym Zs` field indicates how long ago the lock was acquired
 * relative to the bugreport timestamp.
 *
 * No consumers in plan 5 — plan 6 wires this into BugReportAnalyzer.
 */
@Singleton
class WakelockParser @Inject constructor() {

    fun parse(
        lines: Sequence<String>,
        bugreportTimestamp: Long,
        capturedAt: Long,
    ): List<WakelockAcquisition> {
        val events = mutableListOf<WakelockAcquisition>()
        var inWakelockSection = false

        for (line in lines) {
            val trimmed = line.trim()
            when {
                trimmed.startsWith("Wake Locks:") -> {
                    inWakelockSection = true
                }
                inWakelockSection && trimmed.isBlank() -> {
                    inWakelockSection = false
                }
                inWakelockSection -> {
                    val wakelock = parseWakelockLine(trimmed, bugreportTimestamp, capturedAt)
                    if (wakelock != null) events += wakelock
                }
            }
        }
        return events
    }

    private fun parseWakelockLine(
        line: String,
        bugreportTimestamp: Long,
        capturedAt: Long,
    ): WakelockAcquisition? {
        val tagMatch = Regex("'([^']+)'").find(line) ?: return null
        val tag = tagMatch.groupValues[1]

        val pkgMatch = Regex("TAG=([^\\s]+)").find(line) ?: return null
        val packageName = pkgMatch.groupValues[1]

        val acqMatch = Regex("ACQ=-?(?:(\\d+)h)?(?:(\\d+)m)?(?:(\\d+)s)?(?:(\\d+)ms)?").find(line)
        val acqOffsetMillis = acqMatch?.let { parseOffset(it.groupValues) } ?: 0L

        return WakelockAcquisition(
            packageName = packageName,
            wakelockTag = tag,
            acquiredAt = bugreportTimestamp - acqOffsetMillis,
            durationMillis = null,
            source = TelemetrySource.BUGREPORT_IMPORT,
            capturedAt = capturedAt,
        )
    }

    private fun parseOffset(groups: List<String>): Long {
        // groups: [full, h, m, s, ms]
        var millis = 0L
        if (groups.size > 1 && groups[1].isNotEmpty()) {
            millis += groups[1].toLong() * 3_600_000
        }
        if (groups.size > 2 && groups[2].isNotEmpty()) {
            millis += groups[2].toLong() * 60_000
        }
        if (groups.size > 3 && groups[3].isNotEmpty()) {
            millis += groups[3].toLong() * 1_000
        }
        if (groups.size > 4 && groups[4].isNotEmpty()) {
            millis += groups[4].toLong()
        }
        return millis
    }
}
