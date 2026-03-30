package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import javax.inject.Inject
import javax.inject.Singleton

enum class CorrelationPattern {
    INSTALL_THEN_PERMISSION,    // connector line
    PERMISSION_THEN_C2,         // red box
    MULTI_PERMISSION_BURST,     // orange box
    INSTALL_THEN_ADMIN,         // red box
    PRE_LINKED,                 // correlationId-based
    GENERIC_TEMPORAL            // fallback
}

data class EventCluster(
    val events: List<ForensicTimelineEvent>,
    val pattern: CorrelationPattern,
    val label: String
)

object TimelineCategory {
    const val PACKAGE_INSTALL = "package_install"
    const val PACKAGE_UPDATE = "package_update"
    const val PERMISSION_USE = "permission_use"
    const val IOC_MATCH = "ioc_match"
    const val DNS_QUERY = "dns_query"
    const val APP_RISK = "app_risk"
    const val DEVICE_POSTURE = "device_posture"
    const val APP_FOREGROUND = "app_foreground"
    const val APP_BACKGROUND = "app_background"
    const val PACKAGE_UNINSTALL = "package_uninstall"
    const val PACKAGE_DOWNGRADE = "package_downgrade"

    // Surveillance-related categories for multi-permission burst
    val SURVEILLANCE_CATEGORIES = setOf(PERMISSION_USE)
}

/**
 * Partitions forensic timeline events into correlation clusters and standalone events.
 * Implements four named attack-pattern detectors with pattern-specific time windows,
 * plus a generic temporal fallback for remaining events.
 */
@Singleton
class CorrelationEngine @Inject constructor() {

    fun partition(
        events: List<ForensicTimelineEvent>
    ): Pair<List<EventCluster>, List<ForensicTimelineEvent>> {
        val clusters = mutableListOf<EventCluster>()
        val used = mutableSetOf<Long>()

        // Phase 1: Pre-linked correlations (shared correlationId)
        events.filter { it.correlationId.isNotEmpty() }
            .groupBy { it.correlationId }
            .values
            .filter { it.size >= 2 }
            .forEach { group ->
                clusters.add(EventCluster(
                    events = group.sortedBy { it.timestamp },
                    pattern = CorrelationPattern.PRE_LINKED,
                    label = "Linked events"
                ))
                used.addAll(group.map { it.id })
            }

        // Phase 2: Named pattern detectors (order matters — more specific first)
        val remaining = events.filter { it.id !in used && it.packageName.isNotEmpty() }
        val byPackage = remaining.groupBy { it.packageName }

        for ((pkg, pkgEvents) in byPackage) {
            if (pkgEvents.size < 2) continue
            val sorted = pkgEvents.sortedBy { it.timestamp }

            // Pattern: Install-from-unknown-then-admin (unbounded time window)
            detectInstallThenAdmin(sorted, pkg, clusters, used)

            // Pattern: Permission-use-then-C2 (30 min)
            detectPermissionThenC2(sorted, pkg, clusters, used)

            // Pattern: Multi-permission burst (5 min)
            detectMultiPermissionBurst(sorted, pkg, clusters, used)

            // Pattern: Install-then-permission-use (1 hour)
            detectInstallThenPermission(sorted, pkg, clusters, used)
        }

        // Phase 3: Generic temporal fallback for remaining unclustered events
        val stillRemaining = events.filter { it.id !in used && it.packageName.isNotEmpty() }
        val byPkg2 = stillRemaining.groupBy { it.packageName }
        for ((_, pkgEvents) in byPkg2) {
            if (pkgEvents.size < 2) continue
            val sorted = pkgEvents.sortedBy { it.timestamp }
            detectGenericTemporal(sorted, clusters, used)
        }

        val standalone = events.filter { it.id !in used }
        return clusters to standalone
    }

    private fun detectInstallThenAdmin(
        sorted: List<ForensicTimelineEvent>, pkg: String,
        clusters: MutableList<EventCluster>, used: MutableSet<Long>
    ) {
        val installs = sorted.filter {
            it.id !in used && it.category in setOf(
                TimelineCategory.PACKAGE_INSTALL, TimelineCategory.APP_RISK
            ) && it.description.lowercase().let { d ->
                d.contains("sideload") || d.contains("not installed from a trusted")
            }
        }
        val admins = sorted.filter {
            it.id !in used && it.description.lowercase().contains("device admin")
        }

        for (install in installs) {
            val matchingAdmin = admins.firstOrNull { it.id !in used }
            if (matchingAdmin != null) {
                val group = listOf(install, matchingAdmin).sortedBy { it.timestamp }
                clusters.add(EventCluster(group, CorrelationPattern.INSTALL_THEN_ADMIN,
                    "Sideloaded app registered device admin"))
                used.addAll(group.map { it.id })
            }
        }
    }

    private fun detectPermissionThenC2(
        sorted: List<ForensicTimelineEvent>, pkg: String,
        clusters: MutableList<EventCluster>, used: MutableSet<Long>
    ) {
        val permEvents = sorted.filter {
            it.id !in used && it.category == TimelineCategory.PERMISSION_USE
        }
        val c2Events = sorted.filter {
            it.id !in used && (it.category == TimelineCategory.IOC_MATCH ||
                it.category == TimelineCategory.DNS_QUERY && it.iocIndicator.isNotEmpty())
        }

        for (perm in permEvents) {
            val matchingC2 = c2Events.firstOrNull {
                it.id !in used && kotlin.math.abs(it.timestamp - perm.timestamp) <= WINDOW_30_MIN
            }
            if (matchingC2 != null) {
                val group = listOf(perm, matchingC2).sortedBy { it.timestamp }
                clusters.add(EventCluster(group, CorrelationPattern.PERMISSION_THEN_C2,
                    "Permission use followed by C2 communication"))
                used.addAll(group.map { it.id })
            }
        }
    }

    private fun detectMultiPermissionBurst(
        sorted: List<ForensicTimelineEvent>, pkg: String,
        clusters: MutableList<EventCluster>, used: MutableSet<Long>
    ) {
        val permEvents = sorted.filter {
            it.id !in used && it.category == TimelineCategory.PERMISSION_USE
        }
        if (permEvents.size < 3) return

        // Sliding window: find groups of 3+ permission events within 5 min
        var windowStart = 0
        for (i in permEvents.indices) {
            while (permEvents[i].timestamp - permEvents[windowStart].timestamp > WINDOW_5_MIN) {
                windowStart++
            }
            if (i - windowStart + 1 >= 3) {
                val burst = permEvents.subList(windowStart, i + 1).toList()
                if (burst.none { it.id in used }) {
                    clusters.add(EventCluster(burst, CorrelationPattern.MULTI_PERMISSION_BURST,
                        "Multiple surveillance permissions accessed rapidly"))
                    used.addAll(burst.map { it.id })
                }
            }
        }
    }

    private fun detectInstallThenPermission(
        sorted: List<ForensicTimelineEvent>, pkg: String,
        clusters: MutableList<EventCluster>, used: MutableSet<Long>
    ) {
        val installs = sorted.filter {
            it.id !in used && it.category in setOf(
                TimelineCategory.PACKAGE_INSTALL, TimelineCategory.PACKAGE_UPDATE
            )
        }
        val perms = sorted.filter {
            it.id !in used && it.category == TimelineCategory.PERMISSION_USE
        }

        for (install in installs) {
            val matchingPerms = perms.filter {
                it.id !in used && it.timestamp > install.timestamp &&
                    it.timestamp - install.timestamp <= WINDOW_1_HOUR
            }
            if (matchingPerms.isNotEmpty()) {
                val group = (listOf(install) + matchingPerms).sortedBy { it.timestamp }
                clusters.add(EventCluster(group, CorrelationPattern.INSTALL_THEN_PERMISSION,
                    "App installed then accessed permissions"))
                used.addAll(group.map { it.id })
            }
        }
    }

    private fun detectGenericTemporal(
        sorted: List<ForensicTimelineEvent>,
        clusters: MutableList<EventCluster>, used: MutableSet<Long>
    ) {
        var clusterStart = 0
        for (i in 1 until sorted.size) {
            val gap = sorted[i].timestamp - sorted[i - 1].timestamp
            if (gap > WINDOW_30_MIN || gap < 0) {
                emitGenericCluster(sorted, clusterStart, i, clusters, used)
                clusterStart = i
            }
        }
        emitGenericCluster(sorted, clusterStart, sorted.size, clusters, used)
    }

    private fun emitGenericCluster(
        sorted: List<ForensicTimelineEvent>, start: Int, end: Int,
        clusters: MutableList<EventCluster>, used: MutableSet<Long>
    ) {
        val segment = sorted.subList(start, end).filter { it.id !in used }
        if (segment.size >= 2 && segment.map { it.category }.distinct().size >= 2) {
            clusters.add(EventCluster(
                segment.toList(), CorrelationPattern.GENERIC_TEMPORAL,
                "Related events"
            ))
            used.addAll(segment.map { it.id })
        }
    }

    companion object {
        private const val WINDOW_5_MIN = 5 * 60 * 1000L
        private const val WINDOW_30_MIN = 30 * 60 * 1000L
        private const val WINDOW_1_HOUR = 60 * 60 * 1000L
    }
}

/** Shared severity ordinal for timeline components. */
fun severityOrdinal(level: String): Int = when (level.uppercase()) {
    "CRITICAL" -> 3; "HIGH" -> 2; "MEDIUM" -> 1; else -> 0
}
