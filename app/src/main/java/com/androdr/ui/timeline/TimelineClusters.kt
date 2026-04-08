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
    PRE_LINKED,                 // correlationId-based
    GENERIC_TEMPORAL            // fallback
}

/** A group of raw timeline events that share a correlation signal. */
data class EventCluster(
    val events: List<ForensicTimelineEvent>,
    val pattern: CorrelationPattern,
    val label: String
)

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
 * scans and persisted to `forensic_timeline`. Each signal's `details` JSON
 * encodes a comma-separated `member_event_ids` list that this function uses to
 * look up the underlying raw events and bundle them into an [EventCluster].
 *
 * Events referenced by any signal are removed from the standalone list so they
 * render inside their cluster only — not twice.
 */
fun partitionSignals(
    allEvents: List<ForensicTimelineEvent>
): Pair<List<EventCluster>, List<ForensicTimelineEvent>> {
    if (allEvents.isEmpty()) return emptyList<EventCluster>() to emptyList()
    val byId = allEvents.associateBy { it.id }
    val clusters = mutableListOf<EventCluster>()
    val clusteredIds = mutableSetOf<Long>()

    allEvents.asSequence()
        .filter { it.kind == "signal" }
        .forEach { sig ->
            val cluster = buildCluster(sig, byId) ?: return@forEach
            clusters.add(cluster)
            clusteredIds.addAll(cluster.events.map { it.id })
            // Hide the signal row itself from the standalone list.
            clusteredIds.add(sig.id)
        }

    val standalone = allEvents.filter { it.kind != "signal" && it.id !in clusteredIds }
    return clusters to standalone
}

private fun buildCluster(
    sig: ForensicTimelineEvent,
    byId: Map<Long, ForensicTimelineEvent>
): EventCluster? {
    val fields = parseSignalDetails(sig.details)
    val memberIds = fields["member_event_ids"].orEmpty()
        .split(",")
        .mapNotNull { it.trim().toLongOrNull() }
    val members = memberIds.mapNotNull(byId::get).sortedBy { it.startTimestamp }
    if (members.isEmpty()) return null
    val pattern = patternFor(fields["correlation_type"].orEmpty())
    val label = sig.description.ifEmpty { "Correlated events" }
    return EventCluster(members, pattern, label)
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
