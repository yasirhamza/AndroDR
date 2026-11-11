package com.androdr.privacy

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.data.model.TelemetrySource
import com.androdr.util.MAX_DISPLAY_NAME_CHARS
import com.androdr.util.displaySafe
import com.androdr.util.reportSafe

/**
 * The Timeline entries a completed privacy scan writes (spec 2026-11-10 §5.2, §5.5): one entry for the
 * scan, and one per user-installed app in whose code at least one tracker was found. Pure.
 *
 * They state only facts that stay true (what was found in code): never the user's threshold, never an
 * app with network evidence only, never a system app (the scan entry's counts still cover every app).
 * They are information, not detections: `PRIVACY_SCAN`, no rule, no level, tied to no security scan.
 * Text is written in English at scan time, like the Timeline's other rows; untrusted labels and tracker
 * names are sanitised as on the privacy screen.
 */
internal object PrivacyTimelineRows {
    const val CATEGORY_SCAN = "privacy_scan"
    const val CATEGORY_APP = "privacy_app"
    const val MODULE = "privacy_scan"
    const val MAX_NAMED_TRACKERS = 10

    /** Apps fully inspected, partly inspected, and not inspected at all. */
    data class ScanCounts(val inspected: Int, val partial: Int, val failed: Int)

    fun build(
        at: Long,
        counts: ScanCounts,
        results: List<PrivacyAppResult>,
        evidence: List<PrivacyTrackerEvidence>,
        networkStatus: NetworkStatus,
        /** UTC days with at least one attributed lookup; 0 = the network monitor recorded nothing. */
        dnsCoverageDays: Int,
    ): List<ForensicTimelineEvent> {
        val inCode = evidence.filter { it.inCode }.groupBy { it.packageName }
        val apps = results.filter { !it.isSystemApp && inCode.containsKey(it.packageName) }
            .sortedBy { it.packageName }
            .map { appRow(at, it, inCode.getValue(it.packageName)) }
        return listOf(scanRow(at, counts, inCode.size, networkSentence(networkStatus, dnsCoverageDays))) + apps
    }

    private fun scanRow(at: Long, c: ScanCounts, withTrackers: Int, network: String): ForensicTimelineEvent {
        val inspected = c.inspected + c.partial
        val parts = mutableListOf(
            "Privacy scan: $inspected app${if (inspected == 1) "" else "s"} inspected",
            "trackers found in the code of $withTrackers",
        )
        if (c.failed > 0) parts += "${c.failed} could not be inspected"
        if (c.partial > 0) parts += "${c.partial} partly inspected"
        return row(at, CATEGORY_SCAN, parts.joinToString(" · "), network)
    }

    /** As the privacy screen says it: a step that read no lookups is "no network evidence", never "complete". */
    private fun networkSentence(status: NetworkStatus, coverageDays: Int): String = when {
        status == NetworkStatus.FAILED -> "Network evidence could not be read; code findings are not affected."
        coverageDays == 0 && status != NetworkStatus.PENDING ->
            "The network monitor recorded no lookups in the last 30 days, so there is no network evidence."
        else -> networkStatusSentence(status)
    }

    private fun networkStatusSentence(status: NetworkStatus): String = when (status) {
        NetworkStatus.COMPLETE -> "Network evidence was complete."
        NetworkStatus.TRUNCATED -> "Network evidence was incomplete: the DNS log was too large to read in full."
        NetworkStatus.FAILED -> "Network evidence could not be read; code findings are not affected."
        NetworkStatus.PENDING -> "Network evidence was not read."
    }

    private fun appRow(at: Long, app: PrivacyAppResult, trackers: List<PrivacyTrackerEvidence>): ForensicTimelineEvent {
        val label = displaySafe(app.appLabel).ifBlank { reportSafe(app.packageName, MAX_DISPLAY_NAME_CHARS) }
        val n = trackers.size
        val description = "$label: $n tracker${if (n == 1) "" else "s"} found in code"
        val names = trackers.map { displaySafe(it.trackerName).ifBlank { "Tracker #${it.trackerId}" } }.sorted()
        val details = buildList {
            val shown = names.take(MAX_NAMED_TRACKERS).joinToString(", ")
            val more = names.size - MAX_NAMED_TRACKERS
            add("Trackers found in code: " + if (more > 0) "$shown and $more more" else shown)
            val fresh = trackers.count { it.newSinceLastScan }
            if (fresh > 0) add("$fresh new since the previous privacy scan")
            if (app.outcome == InspectOutcome.PARTIAL.name) {
                add("Partly inspected: some of this app's code could not be read.")
            }
        }.joinToString("\n")
        return row(at, CATEGORY_APP, description, details).copy(packageName = app.packageName, appName = label)
    }

    private fun row(at: Long, category: String, description: String, details: String) = ForensicTimelineEvent(
        startTimestamp = at,
        source = MODULE,
        category = category,
        description = description,
        details = details,
        createdAt = at,
        telemetrySource = TelemetrySource.PRIVACY_SCAN,
    )
}
