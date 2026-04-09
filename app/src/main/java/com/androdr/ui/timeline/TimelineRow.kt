package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.sigma.Finding

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
    val combined: List<TimelineRow> = (telemetryRows + findingRows)
        .sortedByDescending { it.timestamp }
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
