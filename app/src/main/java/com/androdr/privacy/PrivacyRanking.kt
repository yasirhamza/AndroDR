package com.androdr.privacy

import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.privacy.model.TrackerCategory

enum class Evidence { CODE, NETWORK, BOTH }

data class TrackerRow(
    val trackerId: Int,
    val name: String,
    val website: String,
    val categories: Set<TrackerCategory>,
    val rawCategories: List<String>,
    val inCode: Boolean,
    val lookups: Int,
    val lookupDays: Int,
    val background: Int?,
    val firstSeen: Long?,
    val lastSeen: Long?,
    val newSinceLastScan: Boolean
) {
    val evidence: Evidence
        get() = when {
            inCode && lookups > 0 -> Evidence.BOTH
            inCode -> Evidence.CODE
            else -> Evidence.NETWORK
        }
}

data class AppPrivacyRow(
    val packageName: String,
    val versionCode: Long,
    val appLabel: String,
    val isSystemApp: Boolean,
    val outcome: InspectOutcome,
    val reason: String?,
    val trackers: List<TrackerRow>,
    val refusedInCode: Int,
    val refusedCategories: Set<TrackerCategory>,
    val newCrossing: Boolean
)

enum class RowSection { NEEDS_ATTENTION, CROSSING, OTHER }

data class PrivacySummary(val crossing: Int, val newCrossing: Int, val notInspected: Int, val scannedAt: Long)

/** One tracker and every app it was found in, each with that app's own evidence row. */
data class TrackerGroup(
    val trackerId: Int,
    val name: String,
    val website: String,
    val categories: Set<TrackerCategory>,
    val apps: List<Pair<AppPrivacyRow, TrackerRow>>
)

/**
 * The single place stored privacy results become ranked rows and a summary; the Dashboard card, the privacy
 * screen and the Apps tab all call it, so they cannot disagree.
 */
object PrivacyRanking {

    private const val CATEGORY_SEPARATOR = '\u001F'

    fun rows(
        results: List<PrivacyAppResult>,
        evidence: List<PrivacyTrackerEvidence>,
        refused: Set<TrackerCategory>,
        showSystemApps: Boolean
    ): List<Pair<RowSection, List<AppPrivacyRow>>> {
        val byPackage = evidence.groupBy { it.packageName }
        val built = results.map { buildRow(it, byPackage[it.packageName].orEmpty(), refused) }
        val crossingOrder = compareByDescending<AppPrivacyRow> { it.refusedInCode }.thenBy { it.appLabel }
        val placed = built.groupBy { sectionOf(it, showSystemApps) }
        return listOf(
            RowSection.NEEDS_ATTENTION to placed[Placement.ATTENTION].orEmpty().sortedWith(crossingOrder),
            RowSection.CROSSING to placed[Placement.CROSSING].orEmpty().sortedWith(crossingOrder),
            RowSection.OTHER to placed[Placement.OTHER].orEmpty().sortedBy { it.appLabel }
        )
    }

    /** Most apps first, then name. Apps keep the order of [rows]. */
    fun byTracker(rows: List<AppPrivacyRow>): List<TrackerGroup> =
        rows.flatMap { app -> app.trackers.map { app to it } }
            .groupBy { it.second.trackerId }
            .map { (id, pairs) ->
                val first = pairs.first().second
                TrackerGroup(id, first.name, first.website, first.categories, pairs)
            }
            .sortedWith(compareByDescending<TrackerGroup> { it.apps.size }.thenBy { it.name })

    /** Computed from [rows] so the card, the screen and the Apps tab share one source of truth. */
    fun summary(
        scan: PrivacyScan,
        results: List<PrivacyAppResult>,
        evidence: List<PrivacyTrackerEvidence>,
        refused: Set<TrackerCategory>,
        showSystemApps: Boolean
    ): PrivacySummary {
        val sections = rows(results, evidence, refused, showSystemApps).toMap()
        val crossing = sections[RowSection.CROSSING].orEmpty()
        val all = sections.values.flatten()
        return PrivacySummary(
            crossing = crossing.size,
            newCrossing = crossing.count { it.newCrossing },
            notInspected = all.count { it.outcome != InspectOutcome.INSPECTED },
            scannedAt = scan.finishedAt ?: scan.startedAt
        )
    }

    private enum class Placement { ATTENTION, CROSSING, OTHER, HIDDEN }

    /** Hidden system apps (the toggle) never reach a visible section except via NEEDS_ATTENTION. */
    private fun sectionOf(row: AppPrivacyRow, showSystemApps: Boolean): Placement {
        val crossing = row.refusedInCode > 0
        val hiddenSystem = row.isSystemApp && !showSystemApps
        return when {
            row.outcome == InspectOutcome.COULD_NOT_INSPECT -> Placement.ATTENTION
            row.outcome == InspectOutcome.PARTIAL && (!crossing || hiddenSystem) -> Placement.ATTENTION
            hiddenSystem -> Placement.HIDDEN
            crossing -> Placement.CROSSING
            else -> Placement.OTHER
        }
    }

    private fun buildRow(
        app: PrivacyAppResult,
        evidence: List<PrivacyTrackerEvidence>,
        refused: Set<TrackerCategory>
    ): AppPrivacyRow {
        val trackers = evidence.map { toTrackerRow(it) }
            .sortedWith(
                compareByDescending<TrackerRow> { t -> t.categories.any { it in refused } }.thenBy { it.name }
            )
        val refusedCode = trackers.filter { t -> t.inCode && t.categories.any { it in refused } }
        return AppPrivacyRow(
            packageName = app.packageName,
            versionCode = app.versionCode,
            appLabel = app.appLabel,
            isSystemApp = app.isSystemApp,
            outcome = parseOutcome(app.outcome),
            reason = app.reason,
            trackers = trackers,
            refusedInCode = refusedCode.size,
            refusedCategories = refusedCode.flatMap { it.categories }.filter { it in refused }.toSet(),
            newCrossing = refusedCode.any { it.newSinceLastScan }
        )
    }

    private fun toTrackerRow(e: PrivacyTrackerEvidence): TrackerRow {
        val raw = if (e.categories.isEmpty()) emptyList() else e.categories.split(CATEGORY_SEPARATOR)
        return TrackerRow(
            trackerId = e.trackerId,
            name = e.trackerName,
            website = e.website,
            categories = raw.map { TrackerCategory.fromLabel(it) }.toSet(),
            rawCategories = raw,
            inCode = e.inCode,
            lookups = e.lookups,
            lookupDays = e.lookupDays,
            background = e.background,
            firstSeen = e.firstSeen,
            lastSeen = e.lastSeen,
            newSinceLastScan = e.newSinceLastScan
        )
    }

    /**
     * A stored outcome that does not parse is treated as [InspectOutcome.COULD_NOT_INSPECT]: the
     * never-falsely-reassuring choice, since it surfaces the app under "needs attention" rather than
     * implying it was inspected.
     */
    private fun parseOutcome(stored: String): InspectOutcome =
        InspectOutcome.entries.firstOrNull { it.name == stored } ?: InspectOutcome.COULD_NOT_INSPECT
}
