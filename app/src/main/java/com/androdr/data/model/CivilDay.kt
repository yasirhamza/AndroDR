package com.androdr.data.model

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * A day-precision time is a calendar date, not a moment (ruling R32). It is stored as UTC midnight
 * of the date the source printed, and always read back in UTC, so it shows that printed date in any
 * viewer's zone and for any capture zone (zone-less reports included). Exact-precision times are
 * instants in the capture zone (R27) and never go through here.
 */
object CivilDay {
    private val FORMAT: DateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE

    /** The stored time of [date]: its UTC midnight, in epoch ms. */
    fun epochMs(date: LocalDate): Long = date.atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli()

    /** The calendar date a day-precision time stands for. */
    fun dateOf(epochMs: Long): LocalDate = Instant.ofEpochMilli(epochMs).atZone(ZoneOffset.UTC).toLocalDate()

    /** The date as `yyyy-MM-dd`. */
    fun format(epochMs: Long): String = FORMAT.format(dateOf(epochMs))
}
