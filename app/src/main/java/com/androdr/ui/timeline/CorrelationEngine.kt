package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Partitions forensic timeline events into correlation clusters and standalone events.
 * A cluster groups related events by the same package within a time window,
 * highlighting attack sequences (install -> permission use -> C2 communication).
 */
@Singleton
class CorrelationEngine @Inject constructor() {

    /**
     * Partitions [events] into (clusters, standalone).
     * Each cluster is a list of 2+ events from the same package with 2+ distinct
     * categories within [CLUSTER_WINDOW_MS].
     */
    fun partition(
        events: List<ForensicTimelineEvent>
    ): Pair<List<List<ForensicTimelineEvent>>, List<ForensicTimelineEvent>> {
        val clusters = mutableListOf<List<ForensicTimelineEvent>>()
        val used = mutableSetOf<Long>()

        // Rule 1: Pre-linked correlations (shared correlationId)
        events.filter { it.correlationId.isNotEmpty() }
            .groupBy { it.correlationId }
            .values
            .filter { it.size >= 2 }
            .forEach { group ->
                clusters.add(group.sortedBy { it.timestamp })
                used.addAll(group.map { it.id })
            }

        // Rule 2: Package-based temporal clustering
        val remaining = events.filter { it.id !in used && it.packageName.isNotEmpty() }
        val byPackage = remaining.groupBy { it.packageName }

        for ((_, pkgEvents) in byPackage) {
            if (pkgEvents.size < 2) continue
            val sorted = pkgEvents.sortedBy { it.timestamp }

            var clusterStart = 0
            for (i in 1 until sorted.size) {
                val gap = sorted[i].timestamp - sorted[i - 1].timestamp
                if (gap > CLUSTER_WINDOW_MS || gap < 0) {
                    emitCluster(sorted, clusterStart, i, clusters, used)
                    clusterStart = i
                }
            }
            emitCluster(sorted, clusterStart, sorted.size, clusters, used)
        }

        val standalone = events.filter { it.id !in used }
        return clusters to standalone
    }

    private fun emitCluster(
        sorted: List<ForensicTimelineEvent>,
        start: Int, end: Int,
        clusters: MutableList<List<ForensicTimelineEvent>>,
        used: MutableSet<Long>
    ) {
        val segment = sorted.subList(start, end)
        if (segment.size >= 2 && segment.map { it.category }.distinct().size >= 2) {
            clusters.add(segment.toList())
            used.addAll(segment.map { it.id })
        }
    }

    companion object {
        private const val CLUSTER_WINDOW_MS = 30 * 60 * 1000L // 30 minutes
    }
}
