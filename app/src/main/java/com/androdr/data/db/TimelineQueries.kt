package com.androdr.data.db

import androidx.sqlite.db.SimpleSQLiteQuery
import com.androdr.data.model.TimelineRowEntity

/**
 * A Timeline keyset position (spec §6): the display order is `time DESC, rowKind ASC, seq DESC`
 * (a finding row sorts above its evidence at the same time). See [TimelineRowEntity.seq].
 */
data class TimelineKey(val time: Long, val rowKind: Int, val seq: Long) {
    companion object {
        /** Display order: newest first; rows before facts at one time; then by `seq`, descending. */
        val DISPLAY_ORDER: Comparator<TimelineKey> = compareByDescending<TimelineKey> { it.time }
            .thenBy { it.rowKind }.thenByDescending { it.seq }
    }
}

/** Which side of a [TimelineKey] a page reads (keyset only, never OFFSET). */
enum class TimelineDirection {
    /** At or after the key, in display order (the inclusive refresh; from the top when the key is null). */
    FROM,

    /** After the key, in display order (append). */
    AFTER,

    /** Before the key, nearest first — ascending (prepend; from the oldest entry when the key is null). */
    BEFORE,
}

/** One built statement and its bind arguments. */
class TimelineSql(val sql: String, val args: List<Any?>) {
    fun toQuery(): SimpleSQLiteQuery = SimpleSQLiteQuery(sql, args.toTypedArray())
}

/**
 * The Timeline's SQL (spec §6), one builder per filter shape ([TimelineShape]). The union of
 * visible event facts and visible `forensic_timeline` rows is read as two keyset arms, each walking
 * one index in display order, which [TimelineDao.page] merges by [TimelineKey.DISPLAY_ORDER]: the
 * row arm by `startTimestamp` (or `(scanResultId, startTimestamp)` / `(packageName, startTimestamp)`),
 * the fact arm by `telemetry_record.eventTime` (or `(packageName, eventTime)`, or
 * `scan_record(scanId, eventTime)` under the scan filter). One SQL `UNION ALL … ORDER BY time,
 * rowKind, id` would sort: SQLite does not treat an arm's constant `rowKind` as ordered and adds a
 * TEMP B-TREE per arm. So each arm is a `LIMIT`ed subquery of one `UNION ALL` statement with no
 * outer `ORDER BY` — one statement, so one consistent read with no transaction (no writer lock) —
 * and [TimelineDao.page] merges the two by [TimelineKey.DISPLAY_ORDER].
 *
 * Visibility: the row arm applies [VisibleRow.SQL]; the fact arm applies [VisibleFact.SQL] (a
 * `COMPLETE` observation, or no observation and pinned, [PinnedFact.SQL]), or under the scan filter
 * the observation's own scan must be `COMPLETE` ([CompleteScan.SQL]).
 *
 * Events only (spec §3): a record is an event record when it carries an event time, so
 * [EVENT_RECORD] (`f.eventTime IS NOT NULL`) is what excludes every snapshot record (the taxonomy
 * gives a snapshot service no event-time field, and an absent value leaves it null). [EXACT_TIME]
 * then leaves out day-precision event facts.
 *
 * Nesting: a fact referenced (`recordId`) by a visible row this same filter shows is nested under
 * that row and left out of the fact arm. A count is what the list shows: the rows, the standalone
 * facts, and each counted row's visible evidence fact (shown nested under it).
 *
 * Under the scan filter the fact arm's tie-break is `scan_record`'s rowid, the column its
 * `(scanId, eventTime)` index orders by. That rowid is not an INTEGER PRIMARY KEY alias, so a
 * `VACUUM` may renumber it: harmless across pagers, but a `VACUUM` must never run while a Timeline
 * pager is open.
 *
 * Columns that have their own index but are not the shape's driving column are written `+col`, so
 * the planner never trades the ordered index for an equality one and a sort.
 */
object TimelineQueries {

    /**
     * One page as one statement: the row arm and (when the filter includes facts) the fact arm, each
     * a subquery holding its first [size] entries in [direction]'s order, joined by `UNION ALL`.
     */
    fun page(filter: TimelineFilter, key: TimelineKey?, direction: TimelineDirection, size: Int): TimelineSql {
        val arms = buildList {
            add(rowArm(filter, key, direction, size))
            if (filter.includesFacts) add(factArm(filter, key, direction, size))
        }
        return TimelineSql(arms.joinToString(" UNION ALL ") { "SELECT * FROM (${it.sql})" }, arms.flatMap { it.args })
    }

    /** The filter's count as one statement: rows + standalone facts + the counted rows' evidence. */
    fun count(filter: TimelineFilter): TimelineSql {
        val parts = buildList {
            add(rowCount(filter))
            add(evidenceCount(filter))
            if (filter.includesFacts) add(factCount(filter))
        }
        return TimelineSql("SELECT " + parts.joinToString(" + ") { "(${it.sql})" }, parts.flatMap { it.args })
    }

    private const val ROW_COLS = "SELECT ${TimelineRowEntity.ROW} AS rowKind, r.id AS id, r.id AS seq, " +
        "r.scanResultId AS scanId, r.startTimestamp AS time, r.category AS category, " +
        "r.packageName AS packageName, r.level AS level, r.ruleId AS ruleId, r.correlationId AS correlationId, " +
        "r.kind AS kind, r.telemetrySource AS telemetrySource, NULL AS bodyHash, r.recordId AS recordId " +
        "FROM forensic_timeline r"

    private const val FACT_VALUE_COLS = "COALESCE(f.category, '') AS category, " +
        "COALESCE(f.packageName, '') AS packageName, NULL AS level, '' AS ruleId, '' AS correlationId, " +
        "'event' AS kind"

    private const val FACT_COLS = "SELECT ${TimelineRowEntity.FACT} AS rowKind, f.id AS id, f.id AS seq, " +
        "-1 AS scanId, f.eventTime AS time, $FACT_VALUE_COLS, f.firstSource AS telemetrySource, " +
        "f.bodyHash AS bodyHash, NULL AS recordId FROM telemetry_record f"

    private const val SCAN_FACT_COLS = "SELECT ${TimelineRowEntity.FACT} AS rowKind, f.id AS id, o.rowid AS seq, " +
        "o.scanId AS scanId, o.eventTime AS time, $FACT_VALUE_COLS, o.source AS telemetrySource, " +
        "f.bodyHash AS bodyHash, NULL AS recordId FROM scan_record o JOIN ScanResult s ON s.id = o.scanId " +
        "JOIN telemetry_record f ON f.id = o.recordId"

    /** An event record (spec §3): it carries an event time. This is what excludes snapshot records. */
    private const val EVENT_RECORD = "f.eventTime IS NOT NULL"

    /** Exact precision: leaves out day-precision event facts (they have no time of day to place). */
    private const val EXACT_TIME = "f.timePrecision = 'EXACT'"

    /** Predicates and their arguments, joined with AND. */
    private class Where {
        val terms = ArrayList<String>()
        val args = ArrayList<Any?>()

        fun add(term: String, vararg values: Any?) {
            terms += term
            args.addAll(values)
        }

        fun addWithArgs(term: String, values: List<Any?>) {
            terms += term
            args.addAll(values)
        }

        fun addAll(other: Where) {
            terms += other.terms
            args.addAll(other.args)
        }

        val sql: String get() = terms.joinToString(" AND ")
    }

    /** The row predicates of [filter] except the keyset; [driving] false writes every column `+col`. */
    private fun rowFilter(filter: TimelineFilter, driving: Boolean): Where = Where().apply {
        add(VisibleRow.SQL)
        val shape = filter.shape
        filter.scanId?.let { add(if (driving) "r.scanResultId = ?" else "+r.scanResultId = ?", it) }
        filter.packageName?.let {
            add(if (driving && shape == TimelineShape.PACKAGE) "r.packageName = ?" else "+r.packageName = ?", it)
        }
        filter.source?.let { add("+r.source = ?", it) }
        val time = if (driving) "r.startTimestamp" else "+r.startTimestamp"
        filter.from?.let { add("$time >= ?", it) }
        filter.to?.let { add("$time <= ?", it) }
        if (filter.levels.isNotEmpty()) {
            val levels = filter.levels.map { it.lowercase() }.distinct().sorted()
            addWithArgs("LOWER(r.level) IN (${levels.joinToString(", ") { "?" }})", levels)
        }
        if (filter.findingsAndEvidenceOnly) add("(r.ruleId != '' OR r.kind = 'signal')")
    }

    /** True for the facts nested under a visible row this filter shows (left out of the fact arm). */
    private fun notNested(filter: TimelineFilter): Where {
        val inner = rowFilter(filter, driving = false)
        return Where().apply {
            addWithArgs("NOT EXISTS (SELECT 1 FROM forensic_timeline r WHERE r.recordId = f.id AND ${inner.sql})",
                inner.args)
        }
    }

    /** The fact predicates of [filter] except visibility, nesting and the keyset. */
    private fun factFilter(filter: TimelineFilter, time: String): Where = Where().apply {
        add(EVENT_RECORD)
        add(EXACT_TIME)
        if (time != "f.eventTime") add("$time IS NOT NULL")
        val shape = filter.shape
        filter.packageName?.let {
            add(if (shape == TimelineShape.PACKAGE) "f.packageName = ?" else "+f.packageName = ?", it)
        }
        filter.source?.let { add("+f.service = ?", it) }
        filter.from?.let { add("$time >= ?", it) }
        filter.to?.let { add("$time <= ?", it) }
    }

    /**
     * The keyset predicate of an arm whose entries all have [rowKind], over its [time] and [seq]
     * columns (display order `time DESC, rowKind ASC, seq DESC`).
     */
    private fun keyset(
        key: TimelineKey?, direction: TimelineDirection, rowKind: Int, time: String, seq: String,
    ): Where = Where().apply {
        if (key == null) return@apply
        val t = key.time
        when (direction) {
            TimelineDirection.FROM, TimelineDirection.AFTER -> when {
                rowKind > key.rowKind -> add("$time <= ?", t)
                rowKind < key.rowKind -> add("$time < ?", t)
                else -> {
                    val cmp = if (direction == TimelineDirection.FROM) "<=" else "<"
                    add("$time <= ? AND ($time < ? OR $seq $cmp ?)", t, t, key.seq)
                }
            }
            TimelineDirection.BEFORE -> when {
                rowKind < key.rowKind -> add("$time >= ?", t)
                rowKind > key.rowKind -> add("$time > ?", t)
                else -> add("$time >= ? AND ($time > ? OR $seq > ?)", t, t, key.seq)
            }
        }
    }

    private fun order(direction: TimelineDirection, time: String, seq: String): String =
        if (direction == TimelineDirection.BEFORE) "ORDER BY $time, $seq" else "ORDER BY $time DESC, $seq DESC"

    private fun rowArm(
        filter: TimelineFilter, key: TimelineKey?, direction: TimelineDirection, size: Int,
    ): TimelineSql {
        val where = rowFilter(filter, driving = true)
        where.addAll(keyset(key, direction, TimelineRowEntity.ROW, "r.startTimestamp", "r.id"))
        return TimelineSql(
            "$ROW_COLS WHERE ${where.sql} ${order(direction, "r.startTimestamp", "r.id")} LIMIT ?",
            where.args + size,
        )
    }

    private fun factArm(
        filter: TimelineFilter, key: TimelineKey?, direction: TimelineDirection, size: Int,
    ): TimelineSql {
        val scan = filter.scanId
        val time = if (scan != null) "o.eventTime" else "f.eventTime"
        val seq = if (scan != null) "o.rowid" else "f.id"
        val where = Where()
        if (scan != null) where.add("o.scanId = ? AND ${CompleteScan.SQL}", scan) else where.add(VisibleFact.SQL)
        where.addAll(factFilter(filter, time))
        where.addAll(notNested(filter))
        where.addAll(keyset(key, direction, TimelineRowEntity.FACT, time, seq))
        val cols = if (scan != null) SCAN_FACT_COLS else FACT_COLS
        return TimelineSql("$cols WHERE ${where.sql} ${order(direction, time, seq)} LIMIT ?", where.args + size)
    }

    private fun rowCount(filter: TimelineFilter): TimelineSql {
        val where = rowFilter(filter, driving = true)
        return TimelineSql("SELECT COUNT(*) FROM forensic_timeline r WHERE ${where.sql}", where.args)
    }

    /** The counted rows' evidence: each row of the filter whose `recordId` fact is visible (shown nested). */
    private fun evidenceCount(filter: TimelineFilter): TimelineSql {
        val where = rowFilter(filter, driving = true)
        where.add("r.recordId IS NOT NULL AND EXISTS (SELECT 1 FROM telemetry_record f WHERE f.id = r.recordId " +
            "AND ${VisibleFact.SQL})")
        return TimelineSql("SELECT COUNT(*) FROM forensic_timeline r WHERE ${where.sql}", where.args)
    }

    private fun factCount(filter: TimelineFilter): TimelineSql {
        val scan = filter.scanId
        val where = Where()
        return if (scan != null) {
            where.add("o.scanId = ? AND ${CompleteScan.SQL}", scan)
            where.addAll(factFilter(filter, "o.eventTime"))
            where.addAll(notNested(filter))
            TimelineSql("SELECT COUNT(*) FROM scan_record o JOIN ScanResult s ON s.id = o.scanId " +
                "JOIN telemetry_record f ON f.id = o.recordId WHERE ${where.sql}", where.args)
        } else {
            where.add(VisibleFact.SQL)
            where.addAll(factFilter(filter, "f.eventTime"))
            where.addAll(notNested(filter))
            TimelineSql("SELECT COUNT(*) FROM telemetry_record f WHERE ${where.sql}", where.args)
        }
    }
}
