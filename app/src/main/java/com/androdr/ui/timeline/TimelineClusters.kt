package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.effectiveCorrelationId
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Correlation pattern buckets used by the Timeline UI to color clusters.
 * Populated from the SIGMA YAML rule `correlation.type` field via
 * [SigmaCorrelationEngine], not from hardcoded Kotlin detectors.
 */
enum class CorrelationPattern {
    INSTALL_THEN_PERMISSION,    // connector line
    PERMISSION_THEN_C2,         // red box
    MULTI_PERMISSION_BURST,     // orange box
    INSTALL_THEN_ADMIN,         // red box
    PRE_LINKED,                 // correlationId-based
    GENERIC_TEMPORAL            // fallback
}

/**
 * A group of timeline members shown as one card. A pre-linked cluster holds its rows in [members].
 * A correlation signal's cluster ([signalRowId] set) starts with no members: they live only in
 * `signal_member` and are loaded page by page through [ClusterMembers] when the card is expanded;
 * [memberCount] is the signal's own count (null for a legacy signal not yet backfilled).
 */
data class EventCluster(
    val members: List<TimelineMember>,
    val pattern: CorrelationPattern,
    val label: String,
    val startTimestamp: Long,
    val endTimestamp: Long,
    val signalRowId: Long? = null,
    val memberCount: Int? = null,
) {
    /** A stable list key: the signal row, or the first member. */
    val key: String
        get() = signalRowId?.let { "signal_$it" }
            ?: "prelinked_" + ((members.firstOrNull() as? TimelineMember.RowMember)?.row?.id ?: startTimestamp)

    /** How many members the card announces. */
    val size: Int get() = memberCount ?: members.size
}

/** Shared severity ordinal for timeline components. */
fun severityOrdinal(level: String): Int = when (level.uppercase()) {
    "CRITICAL" -> 3; "HIGH" -> 2; "MEDIUM" -> 1; else -> 0
}


private val signalJson = Json { ignoreUnknownKeys = true; isLenient = true }

/**
 * Partitions a list of [ForensicTimelineEvent] rows (both `kind = "event"` and
 * `kind = "signal"` mixed together, as returned by the DAO) into clusters and
 * standalone events for the timeline UI.
 *
 * Signal rows are produced by [com.androdr.sigma.SigmaCorrelationEngine] during
 * scans and persisted to `forensic_timeline`. Each becomes an [EventCluster] whose
 * members (rows and stored facts, kept only in `signal_member`) load on expand through
 * [ClusterMembers]. The members also stay standalone Timeline entries (spec §6: the
 * row-and-fact union of the Timeline arrives in Task C4).
 */
fun partitionSignals(
    allEvents: List<ForensicTimelineEvent>
): Pair<List<EventCluster>, List<ForensicTimelineEvent>> {
    if (allEvents.isEmpty()) return emptyList<EventCluster>() to emptyList()
    val clusters = mutableListOf<EventCluster>()
    val clusteredIds = mutableSetOf<Long>()

    // Pass 1 — explicit correlation signals produced by SigmaCorrelationEngine. The signal row
    // is the cluster head; its members load on expand.
    allEvents.asSequence()
        .filter { it.kind == "signal" }
        .forEach { sig ->
            clusters.add(buildCluster(sig))
            // Hide the signal row itself from the standalone list.
            clusteredIds.add(sig.id)
        }

    // Pass 2 — implicit pre-linkage via effective correlationId. Two sources
    // feed this pass:
    //   * DNS-sourced findings + ioc_match rows share "dns:<domain>" stamped
    //     by TimelineAdapter at write time (cross-category, cross-source).
    //   * Every row tied to an installed package gets a synthetic
    //     "pkg:<packageName>" computed at read time, so a package's install
    //     row, foreground/background events, permission_use records, and
    //     any finding collapse into one card per app.
    // Cluster membership requires at least two members so unique packages
    // still render as standalone rows.
    allEvents.asSequence()
        .filter { it.kind != "signal" && it.id !in clusteredIds }
        .groupBy { it.effectiveCorrelationId() }
        .filter { (key, members) -> key.isNotBlank() && members.size >= PRE_LINKED_MIN_MEMBERS }
        .forEach { (_, members) ->
            val sorted = members.sortedBy { it.startTimestamp }
            clusters.add(
                EventCluster(
                    members = sorted.map { TimelineMember.RowMember(it) },
                    pattern = CorrelationPattern.PRE_LINKED,
                    label = prelinkedLabel(sorted),
                    startTimestamp = sorted.first().startTimestamp,
                    endTimestamp = sorted.last().startTimestamp,
                )
            )
            clusteredIds.addAll(sorted.map { it.id })
        }

    val standalone = allEvents.filter { it.kind != "signal" && it.id !in clusteredIds }
    return clusters to standalone
}

private const val PRE_LINKED_MIN_MEMBERS = 2

/**
 * Picks a human-readable label for a pre-linked cluster. Order of preference:
 *   1. Highest-severity finding (`app_risk` / `device_posture`) — anchors
 *      clusters with a genuine detection on the most actionable text.
 *   2. Package display name if the cluster is a pkg: group — this dominates
 *      app-level clusters, which are usually lifecycle + install + permission
 *      use events without an actual finding. Reading "com.whatsapp (29)"
 *      is more useful than reading "App opened: WhatsApp (29)".
 *   3. The first member's description — last-ditch fallback for DNS
 *      clusters that somehow lack a finding (shouldn't happen, but cheap).
 */
private fun prelinkedLabel(members: List<ForensicTimelineEvent>): String {
    // Prefer the first finding-category member as the label anchor.
    // Severity ranking now lives on the [TimelineRow.FindingRow] variant
    // rendered by `TimelineScreen`; cluster labels are derived only from
    // the telemetry members available here.
    val bestFinding = members
        .firstOrNull { it.category == "app_risk" || it.category == "device_posture" }
    if (bestFinding != null) return bestFinding.description

    val firstPackageName = members.firstNotNullOfOrNull { it.packageName.takeIf { p -> p.isNotBlank() } }
    val firstAppName = members.firstNotNullOfOrNull { it.appName.takeIf { n -> n.isNotBlank() } }
    if (firstPackageName != null) {
        return if (firstAppName != null && firstAppName != firstPackageName) {
            "$firstAppName ($firstPackageName)"
        } else {
            firstPackageName
        }
    }

    return members.first().description
}

private fun buildCluster(sig: ForensicTimelineEvent): EventCluster {
    val fields = parseSignalDetails(sig.details)
    return EventCluster(
        members = emptyList(),
        pattern = patternFor(fields["correlation_type"].orEmpty()),
        label = sig.description.ifEmpty { "Correlated events" },
        startTimestamp = sig.startTimestamp,
        endTimestamp = sig.endTimestamp ?: sig.startTimestamp,
        signalRowId = sig.id,
        memberCount = fields[com.androdr.sigma.SigmaCorrelationEngine.MEMBER_COUNT]?.toIntOrNull(),
    )
}

private fun parseSignalDetails(details: String): Map<String, String> {
    if (details.isBlank()) return emptyMap()
    return runCatching {
        signalJson.parseToJsonElement(details).jsonObject.mapValues {
            it.value.jsonPrimitive.content
        }
    }.getOrDefault(emptyMap())
}

private fun patternFor(correlationType: String): CorrelationPattern =
    when (correlationType.lowercase()) {
        "temporal_ordered" -> CorrelationPattern.INSTALL_THEN_PERMISSION
        "temporal_unordered" -> CorrelationPattern.GENERIC_TEMPORAL
        "event_count" -> CorrelationPattern.MULTI_PERMISSION_BURST
        "value_count" -> CorrelationPattern.MULTI_PERMISSION_BURST
        else -> CorrelationPattern.GENERIC_TEMPORAL
    }
