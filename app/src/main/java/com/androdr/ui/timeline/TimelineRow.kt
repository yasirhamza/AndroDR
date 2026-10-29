package com.androdr.ui.timeline

import com.androdr.data.db.TimelineKey
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TimelineRowEntity
import com.androdr.data.store.DecodedRecord
import com.androdr.sigma.Finding

/**
 * One row of the Timeline UI (spec §6). The paged list holds [Entry] rows — the keyset union of
 * event facts ([EventRow]) and `forensic_timeline` rows ([StoredRow]) — with a [DayHeader] between
 * days; the pinned section above it holds the current findings ([FindingRow]). The screen renders
 * each variant through an exhaustive `when`, so every variant has a visual treatment.
 */
sealed interface TimelineRow {
    /** The time the row is placed at, in epoch ms. */
    val timestamp: Long

    /** A row the Timeline query returned, at its keyset position. */
    sealed interface Entry : TimelineRow {
        val entity: TimelineRowEntity
        val key: TimelineKey get() = entity.key
        override val timestamp: Long get() = entity.time
    }

    /** An event fact, read in place from the store (never copied into `forensic_timeline`). */
    data class EventRow(override val entity: TimelineRowEntity, val record: DecodedRecord) : Entry

    /**
     * A finding row, a correlation signal or a detected change. [evidence] is the fact the row
     * points at (`recordId`), nested under it: the fact is not also listed on its own.
     */
    data class StoredRow(
        override val entity: TimelineRowEntity,
        val event: ForensicTimelineEvent,
        val evidence: DecodedRecord?,
    ) : Entry

    /**
     * The start of one day of the list ([com.androdr.data.db.TimelineFilter.dayOf]), placed before
     * the entry at [anchor]. A day-precision entry sorts at its date's UTC midnight but groups under
     * its own date (R32), so in a zone far from UTC one day's header can appear twice; [anchor]
     * keeps each header's list key unique.
     */
    data class DayHeader(val day: Long, val anchor: TimelineKey? = null) : TimelineRow {
        override val timestamp: Long get() = day
    }

    /** A current finding (the latest scan's), shown in the pinned section. */
    data class FindingRow(
        val finding: Finding,
        val anchorEvent: ForensicTimelineEvent? = null,
        val duplicateCount: Int = 1,
        val firstSeenTimestamp: Long? = null,
    ) : TimelineRow {
        override val timestamp: Long
            get() = anchorEvent?.startTimestamp ?: Long.MAX_VALUE
    }
}

/**
 * The scan findings the timeline shows as [TimelineRow.FindingRow]s. Untriggered
 * ("safe state") findings belong to the Device Audit screen, and correlation findings
 * are already on the timeline as their signal row -- the cluster head that expands
 * into the member events -- so listing them again would show every chain twice (#350).
 */
fun timelineFindingRows(findings: List<Finding>): List<Finding> =
    findings.filter { it.triggered && it.category != com.androdr.sigma.FindingCategory.CORRELATION }

/** How many current findings the pinned section lists before "Show all" (ruling R34). */
internal const val PINNED_FINDINGS_PREVIEW = 3

/**
 * The pinned section's cards (ruling R34): the current findings most severe first (ties keep their
 * scan order); only the first [PINNED_FINDINGS_PREVIEW] unless [showAll], so a large import's
 * findings never bury the Timeline below them.
 */
internal fun pinnedFindings(findings: List<Finding>, showAll: Boolean): List<Finding> {
    val bySeverity = findings.sortedByDescending { severityOrdinal(it.level) }
    return if (showAll) bySeverity else bySeverity.take(PINNED_FINDINGS_PREVIEW)
}

/** Where "Matched record" navigates: a fact by id, as scan [scanId] observed it when non-null. */
internal data class FactTarget(val factId: Long, val scanId: Long?)

/**
 * "Matched record" (spec §6): the row's `recordId`, with the row's scan (when it has one) so the fact
 * reads with the envelope the finding matched; null for a row without a matched record.
 */
internal fun matchedRecordTarget(event: ForensicTimelineEvent): FactTarget? =
    event.recordId?.let { FactTarget(it, event.scanResultId.takeIf { scan -> scan > 0 }) }
