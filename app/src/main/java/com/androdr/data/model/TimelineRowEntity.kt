package com.androdr.data.model

import com.androdr.data.db.TimelineKey

/**
 * One entry of the Timeline union (spec §6), as the keyset query reads it: a visible
 * `forensic_timeline` row ([rowKind] [ROW]) or a visible event fact ([rowKind] [FACT]). The fact
 * branch fills its non-null columns with `COALESCE` (an empty category, package, rule and
 * correlation id; [kind] `event`).
 *
 * - [id]: the row id, or the fact id.
 * - [seq]: the keyset tie-break inside one time: the row id, the fact id, or — when the scan filter
 *   reads facts through `scan_record(scanId, eventTime)` — the observation's rowid, the column that
 *   index orders by after the time.
 * - [scanId]: the row's `scanResultId`; for a fact, the filtered scan, or −1 when no scan filter.
 * - [recordId]: the fact a row points at (a finding row's evidence, nested under it); null for facts.
 * - [bodyHash]: the fact's body, null for rows.
 * - [timePrecision]: the row's `timestampPrecision` or the fact's `timePrecision` (case varies);
 *   [isDay] when it is a calendar date ([CivilDay], ruling R32).
 *
 * A plain class: it holds a `ByteArray`.
 */
@Suppress("LongParameterList") // one constructor parameter per selected column (Room maps by name)
class TimelineRowEntity(
    val rowKind: Int,
    val id: Long,
    val seq: Long,
    val scanId: Long,
    val time: Long,
    val category: String,
    val packageName: String,
    val level: String?,
    val ruleId: String,
    val correlationId: String,
    val kind: String,
    val telemetrySource: TelemetrySource,
    val bodyHash: ByteArray?,
    val recordId: Long?,
    val timePrecision: String,
) {
    val key: TimelineKey get() = TimelineKey(time, rowKind, seq)

    /** A day-precision entry: [time] is a calendar date (UTC midnight), not a moment. */
    val isDay: Boolean get() = timePrecision.equals(DAY, ignoreCase = true)

    companion object {
        /** A `forensic_timeline` row: a finding row, a correlation signal, or a detected change. */
        const val ROW = 0

        /** An event fact, read in place from the store. Rows sort before facts at one time. */
        const val FACT = 1

        const val DAY = "day"
    }
}
