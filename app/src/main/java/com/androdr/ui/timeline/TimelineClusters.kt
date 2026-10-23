package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
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
    GENERIC_TEMPORAL            // fallback
}

/**
 * A group of timeline members shown as one card. A correlation signal's cluster ([signalRowId] set)
 * starts with no [members]: they live only in `signal_member` and are loaded page by page through
 * [ClusterMembers] when the card is expanded; [memberCount] is the signal's own count (null for a
 * legacy signal not yet backfilled).
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
            ?: "members_" + ((members.firstOrNull() as? TimelineMember.RowMember)?.row?.id ?: startTimestamp)

    /** How many members the card announces. */
    val size: Int get() = memberCount ?: members.size
}

/** Shared severity ordinal for timeline components. */
fun severityOrdinal(level: String): Int = when (level.uppercase()) {
    "CRITICAL" -> 3; "HIGH" -> 2; "MEDIUM" -> 1; else -> 0
}


private val signalJson = Json { ignoreUnknownKeys = true; isLenient = true }

/**
 * The cluster a correlation signal row (`kind = "signal"`, written by
 * [com.androdr.sigma.SigmaCorrelationEngine]) heads on the Timeline. Its members (rows and stored
 * facts, kept only in `signal_member`) load on expand through [ClusterMembers]; they also stay
 * Timeline entries of their own. There is no read-time pre-linked grouping: the Timeline is paged,
 * and a roll-up across rows would change with the page boundaries (spec §6: no cross-page roll-up).
 */
fun signalCluster(sig: ForensicTimelineEvent): EventCluster {
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
