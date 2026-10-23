package com.androdr.scanner.bugreport

import java.time.DateTimeException
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZoneOffset

/**
 * The one time base of a bug-report import (ruling R27): every dumpsys wall-clock time (the
 * capture header, AppOps access times, package install/update times, battery day boundaries) is
 * read in the capture device's own zone, `persist.sys.timezone` from the report's SYSTEM
 * PROPERTIES, and turned into an epoch instant with [ZoneId] rules, so DST applies per timestamp.
 *
 * Without that property the import falls back to a deterministic UTC wall clock ([assumedUtc]) and
 * says so ([NOTE_ASSUMED_UTC]); it never mixes bases, and never uses the analyzing device's zone.
 * In a DST gap a wall time is shifted forward by the gap; in an overlap the earlier offset is used
 * (`java.time` defaults), so the result is deterministic.
 */
class DumpsysClock private constructor(val zone: ZoneId, val assumedUtc: Boolean) {

    /** [time] on the capture device's wall clock, as epoch milliseconds. */
    fun epochMs(time: LocalDateTime): Long = time.atZone(zone).toInstant().toEpochMilli()

    /** The start of [day] on the capture device's wall clock, as epoch milliseconds. */
    fun startOfDayMs(day: LocalDate): Long = day.atStartOfDay(zone).toInstant().toEpochMilli()

    override fun toString(): String = if (assumedUtc) "DumpsysClock(UTC, assumed)" else "DumpsysClock($zone)"

    companion object {
        const val TIMEZONE_PROPERTY = "persist.sys.timezone"

        /** The import note shown when the report names no zone. */
        const val NOTE_ASSUMED_UTC =
            "The report does not name its time zone (persist.sys.timezone): times assume UTC."

        /** The fallback: wall-clock times read as UTC, flagged as an assumption. */
        val ASSUMED_UTC = DumpsysClock(ZoneOffset.UTC, assumedUtc = true)

        /** The clock of a capture zone id such as "Asia/Qatar"; [ASSUMED_UTC] when blank or unknown. */
        fun of(zoneId: String?): DumpsysClock {
            val id = zoneId?.trim().orEmpty()
            if (id.isEmpty()) return ASSUMED_UTC
            return try {
                DumpsysClock(ZoneId.of(id), assumedUtc = false)
            } catch (_: DateTimeException) {
                ASSUMED_UTC
            }
        }

        /** The clock named by `persist.sys.timezone` in a SYSTEM PROPERTIES section ([text] may be null). */
        fun fromSystemProperties(text: String?): DumpsysClock =
            of(text?.let { GetpropParser().property(it.lineSequence(), TIMEZONE_PROPERTY) })
    }
}
