package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.sigma.Finding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Thread-local date formatter for date-group labels (SimpleDateFormat is not thread-safe). */
private val DATE_GROUP_FORMAT = ThreadLocal.withInitial {
    SimpleDateFormat("MMM dd, yyyy", Locale.US)
}

/**
 * A single row in the timeline UI. Sealed type with two variants that
 * enforce the spec §3 layer separation at the UI level:
 *
 * - [TelemetryRow] wraps a pure-observation [ForensicTimelineEvent] with
 *   no severity. Rendered as a neutral entry — no severity badge, low
 *   visual weight.
 * - [FindingRow] wraps a rule-produced [Finding] with a severity, category,
 *   and ruleId. Rendered with a severity badge and category indicator.
 *
 * The [TimelineViewModel] merges telemetry events and findings into a
 * single chronological stream of `TimelineRow`. The `Screen` renders
 * each variant via a `when` exhaustive branch so the compiler enforces
 * that every variant has a visual treatment.
 *
 * See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §10 for the rationale.
 */
/**
 * Pure merge logic extracted from [TimelineViewModel] so it can be unit
 * tested without Hilt or Room. Wraps telemetry events and findings into
 * a chronologically sorted list of [TimelineRow], applies the
 * `hideInformationalTelemetry` filter, and computes finding references
 * via rule-id matching.
 */
fun mergeTimelineRows(
    events: List<ForensicTimelineEvent>,
    findings: List<Finding>,
    hideInformationalTelemetry: Boolean
): List<TimelineRow> {
    val findingsByRuleId: Map<String, List<Finding>> = findings.groupBy { it.ruleId }
    val telemetryRows = events.map { event ->
        val refIds = if (event.ruleId.isNotEmpty()) {
            findingsByRuleId[event.ruleId].orEmpty().map { it.ruleId }
        } else emptyList()
        TimelineRow.TelemetryRow(event = event, referencedByFindingIds = refIds)
    }
    val findingRows = findings.map { finding ->
        val anchor = events.firstOrNull { it.ruleId == finding.ruleId }
        TimelineRow.FindingRow(finding = finding, anchorEvent = anchor)
    }
    val combined: List<TimelineRow> = rollUpFindings(telemetryRows + findingRows)
    return if (hideInformationalTelemetry) {
        combined.filter { row ->
            when (row) {
                is TimelineRow.TelemetryRow -> row.referencedByFindingIds.isNotEmpty()
                is TimelineRow.FindingRow -> true
            }
        }
    } else {
        combined
    }
}

/**
 * Groups duplicate [TimelineRow.FindingRow] entries by (ruleId, packageName)
 * and keeps only the most recent occurrence per group with a `duplicateCount`
 * badge. [TimelineRow.TelemetryRow] entries pass through unchanged.
 *
 * This is a display-only rollup — raw events in the database are untouched.
 */
internal fun rollUpFindings(rows: List<TimelineRow>): List<TimelineRow> {
    val telemetryRows = rows.filterIsInstance<TimelineRow.TelemetryRow>()
    val findingRows = rows.filterIsInstance<TimelineRow.FindingRow>()

    val rolledUp = findingRows
        .groupBy { it.finding.ruleId to (it.finding.matchContext["package_name"] ?: "") }
        .map { (_, group) ->
            val mostRecent = group.maxBy { it.timestamp }
            val earliest = group.minBy { it.timestamp }
            mostRecent.copy(
                duplicateCount = group.size,
                firstSeenTimestamp = earliest.timestamp,
            )
        }

    return (telemetryRows + rolledUp).sortedByDescending { it.timestamp }
}

sealed interface TimelineRow {
    /** Timestamp used to sort rows chronologically. */
    val timestamp: Long

    data class TelemetryRow(
        val event: ForensicTimelineEvent,
        val referencedByFindingIds: List<String> = emptyList(),
    ) : TimelineRow {
        override val timestamp: Long get() = event.startTimestamp
    }

    data class FindingRow(
        val finding: Finding,
        val anchorEvent: ForensicTimelineEvent? = null,
        val duplicateCount: Int = 1,
        val firstSeenTimestamp: Long? = null,
    ) : TimelineRow {
        /**
         * Timestamp sourced from the anchor event when one exists; otherwise
         * [Long.MAX_VALUE] so anchorless findings sort to the end of the
         * timeline (most recent) deterministically. Use an anchor event when
         * possible for better chronological placement.
         */
        override val timestamp: Long
            get() = anchorEvent?.startTimestamp ?: Long.MAX_VALUE
    }
}

/**
 * Groups a filtered list of [TimelineRow] into date-bucketed [DateGroup]s
 * ready for rendering. Telemetry rows are partitioned into correlation
 * clusters and standalone events via [partitionSignals].
 *
 * Pure function — no Android dependencies — so it can be unit-tested.
 */
fun buildDateGroups(rows: List<TimelineRow>): List<DateGroup> {
    if (rows.isEmpty()) return emptyList()

    val telemetryEvents = rows
        .filterIsInstance<TimelineRow.TelemetryRow>()
        .map { it.event }
    val (clusters, standaloneEvents) = if (telemetryEvents.isNotEmpty()) {
        partitionSignals(telemetryEvents)
    } else {
        emptyList<EventCluster>() to emptyList<ForensicTimelineEvent>()
    }

    val telemetryByEventId = rows
        .filterIsInstance<TimelineRow.TelemetryRow>()
        .associateBy { it.event.id }
    val standaloneRows = standaloneEvents.mapNotNull { telemetryByEventId[it.id] }
    val findingRows = rows.filterIsInstance<TimelineRow.FindingRow>()

    val fmt = DATE_GROUP_FORMAT.get()!!
    fun dateKey(ts: Long) = if (ts > 0) fmt.format(Date(ts)) else "Unknown Date"

    data class Bucket(
        val findings: MutableList<TimelineRow.FindingRow> = mutableListOf(),
        val clusters: MutableList<EventCluster> = mutableListOf(),
        val standalone: MutableList<TimelineRow.TelemetryRow> = mutableListOf(),
    )
    val buckets = mutableMapOf<String, Bucket>()

    findingRows.forEach { row ->
        buckets.getOrPut(dateKey(row.timestamp)) { Bucket() }.findings.add(row)
    }
    clusters.forEach { cluster ->
        buckets.getOrPut(dateKey(cluster.events.first().startTimestamp)) { Bucket() }
            .clusters.add(cluster)
    }
    standaloneRows.forEach { row ->
        buckets.getOrPut(dateKey(row.timestamp)) { Bucket() }.standalone.add(row)
    }

    return buckets.map { (label, bucket) ->
        DateGroup(
            label = label,
            findingRows = bucket.findings.sortedByDescending { it.timestamp },
            clusters = bucket.clusters.sortedByDescending { c ->
                c.events.maxOfOrNull { it.startTimestamp } ?: 0L
            },
            standaloneRows = bucket.standalone.sortedByDescending { it.timestamp },
        )
    }.sortedByDescending { group ->
        val maxFinding = group.findingRows.maxOfOrNull { it.timestamp } ?: 0L
        val maxCluster = group.clusters.maxOfOrNull { c ->
            c.events.maxOfOrNull { it.startTimestamp } ?: 0L
        } ?: 0L
        val maxStandalone = group.standaloneRows.maxOfOrNull { it.timestamp } ?: 0L
        maxOf(maxFinding, maxCluster, maxStandalone)
    }
}
