package com.androdr.data.db

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
     * The day [time] falls on in [zone], as the epoch ms of its start; [UNKNOWN_DAY] for a time of
     * zero or less (a finding with no event time), which groups under "Unknown date".
     */
    fun dayOf(time: Long): Long = if (time <= 0L) {
        UNKNOWN_DAY
    } else {
        Instant.ofEpochMilli(time).atZone(zone).toLocalDate().atStartOfDay(zone).toInstant().toEpochMilli()
    }

    /** This filter narrowed to one day ([dayOf]'s value), for a date header's count. */
    fun forDay(day: Long): TimelineFilter {
        val (start, end) = if (day == UNKNOWN_DAY) {
            Long.MIN_VALUE to 0L
        } else {
            val date = Instant.ofEpochMilli(day).atZone(zone).toLocalDate()
            day to date.plusDays(1).atStartOfDay(zone).toInstant().toEpochMilli() - 1
        }
        return copy(from = maxOf(from ?: Long.MIN_VALUE, start), to = minOf(to ?: Long.MAX_VALUE, end))
    }

    companion object {
        const val UNKNOWN_DAY = Long.MIN_VALUE
    }
}

/** The filter that drives each arm's index (precedence: scan, package, source, none). */
enum class TimelineShape { ALL, SCAN, PACKAGE, SOURCE }
