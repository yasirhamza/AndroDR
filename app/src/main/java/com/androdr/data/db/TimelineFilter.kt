package com.androdr.data.db

import com.androdr.data.model.CivilDay
import java.time.Instant
import java.time.ZoneId

/**
 * What the Timeline shows (spec §6). Every field narrows the one union of visible event facts and
 * visible `forensic_timeline` rows:
 * - [scanId]: one scan's rows and the facts it observed (read through `scan_record(scanId, eventTime)`);
 * - [packageName]: rows and facts of one package;
 * - [source]: rows of one producing module (`forensic_timeline.source`) and facts of one service;
 * - [from] / [to]: an inclusive time range, in epoch ms;
 * - [levels]: finding rows of these severities only (SQL on `level`, case-insensitive); no facts;
 * - [findingsAndEvidenceOnly]: finding and signal rows only, their evidence nested under them; no facts.
 *
 * [zone] sets day boundaries (date headers and their counts). Bug-report times are capture-zone
 * instants already (ruling R27), so one zone groups every source alike.
 */
data class TimelineFilter(
    val scanId: Long? = null,
    val packageName: String? = null,
    val source: String? = null,
    val from: Long? = null,
    val to: Long? = null,
    val levels: Set<String> = emptySet(),
    val findingsAndEvidenceOnly: Boolean = false,
    val zone: ZoneId = ZoneId.systemDefault(),
    /**
     * Set by [forDay] only (a date header's count): the header's calendar date as its UTC midnight,
     * so day-precision entries of that date count under it (ruling R32).
     */
    val civilDay: Long? = null,
) {
    /** The index-driving filter: one SQL builder per shape (see [TimelineQueries]). */
    val shape: TimelineShape
        get() = when {
            scanId != null -> TimelineShape.SCAN
            packageName != null -> TimelineShape.PACKAGE
            source != null -> TimelineShape.SOURCE
            else -> TimelineShape.ALL
        }

    /** Whether event facts take part: the severity and findings-only views show timeline rows alone. */
    val includesFacts: Boolean get() = levels.isEmpty() && !findingsAndEvidenceOnly

    /**
     * The day an entry at [time] groups under, as the epoch ms of that day's start in [zone];
     * [UNKNOWN_DAY] for a time of zero or less (a finding with no event time), "Unknown date".
     * An exact time is an instant: its date in [zone]. A day-precision time ([isDay]) is a calendar
     * date stored as UTC midnight (ruling R32): its UTC date, started in [zone], so it groups under
     * the date the source printed whatever the viewer's zone.
     */
    fun dayOf(time: Long, isDay: Boolean = false): Long = when {
        time <= 0L -> UNKNOWN_DAY
        isDay -> CivilDay.dateOf(time).atStartOfDay(zone).toInstant().toEpochMilli()
        else -> Instant.ofEpochMilli(time).atZone(zone).toLocalDate().atStartOfDay(zone).toInstant().toEpochMilli()
    }

    /** This filter narrowed to one day ([dayOf]'s value), for a date header's count. */
    fun forDay(day: Long): TimelineFilter {
        if (day == UNKNOWN_DAY) return copy(to = minOf(to ?: 0L, 0L))
        val date = Instant.ofEpochMilli(day).atZone(zone).toLocalDate()
        val end = date.plusDays(1).atStartOfDay(zone).toInstant().toEpochMilli() - 1
        return copy(from = maxOf(from ?: Long.MIN_VALUE, day), to = minOf(to ?: Long.MAX_VALUE, end),
            civilDay = CivilDay.epochMs(date))
    }

    companion object {
        const val UNKNOWN_DAY = Long.MIN_VALUE
    }
}

/** The filter that drives each arm's index (precedence: scan, package, source, none). */
enum class TimelineShape { ALL, SCAN, PACKAGE, SOURCE }
