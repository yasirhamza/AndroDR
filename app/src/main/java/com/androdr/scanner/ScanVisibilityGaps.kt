package com.androdr.scanner

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure
import com.androdr.ioc.FeedCoverage

/** [ScannerFailure.missingSources] values for CAMPAIGN_SOURCES_NOT_LOADED (#394). */
internal const val MISSING_SOURCE_RULES_REPO = "rules_repo"
internal const val MISSING_SOURCE_MVT = "mvt"

/**
 * Sentinel entries for gaps in what a scan could see: no threat-intel feed rows yet (offline
 * first run, after the v19 table reset: FEEDS_NOT_LOADED), rows present but a campaign-key
 * source missing (a failed or unverified rules-repo fetch, MVT not yet synced:
 * CAMPAIGN_SOURCES_NOT_LOADED, whose message names the source), and the DNS tunnel being off.
 * None is a crash ([NotEvaluatedReason] sentinels are excluded from `realFailureCount`).
 * Per-campaign check state is follow-up #394.
 */
internal fun scanVisibilityGaps(coverage: FeedCoverage, dnsMonitorRunning: Boolean): List<ScannerFailure> = buildList {
    if (coverage.rows == 0) {
        add(
            ScannerFailure(
                scanner = "threat_intel",
                exception = NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel,
                message = "threat-intel feeds not loaded yet"
            )
        )
    } else {
        val missing = listOfNotNull(
            if (coverage.rulesRepoLoaded) null
            else "the rules-repo threat lists did not load, so the copy built into the app was checked instead",
            if (coverage.mvtLoaded) null
            else "the MVT collections did not load, so their campaign indicators were not checked",
        )
        if (missing.isNotEmpty()) {
            add(
                ScannerFailure(
                    scanner = "threat_intel",
                    exception = NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.sentinel,
                    message = missing.joinToString("; "),
                    missingSources = listOfNotNull(
                        if (coverage.rulesRepoLoaded) null else MISSING_SOURCE_RULES_REPO,
                        if (coverage.mvtLoaded) null else MISSING_SOURCE_MVT,
                    ),
                )
            )
        }
    }
    if (!dnsMonitorRunning) {
        add(
            ScannerFailure(
                scanner = "dns_monitor",
                exception = NotEvaluatedReason.DNS_MONITOR_OFF.sentinel,
                message = "DNS monitoring was off"
            )
        )
    }
}

/**
 * [scanVisibilityGaps] for a live scan, tolerating failing coverage queries (row count, source
 * EXISTS): the state is then unknown, so no feeds entry is claimed and one real failure is
 * recorded instead. These are plain DAO calls that used to run unguarded ahead of every scanner.
 */
@Suppress("TooGenericExceptionCaught")
internal suspend fun visibilityGapsOrFailure(
    coverage: suspend () -> FeedCoverage,
    dnsMonitorRunning: Boolean,
): List<ScannerFailure> = try {
    scanVisibilityGaps(coverage(), dnsMonitorRunning)
} catch (c: kotlinx.coroutines.CancellationException) {
    throw c
} catch (e: Exception) {
    listOf(
        ScannerFailure(
            scanner = "visibility_gaps",
            exception = e::class.simpleName ?: "Exception",
            message = "could not tell whether threat-intel feeds are loaded"
        )
    ) + scanVisibilityGaps(FeedCoverage(1, true, true), dnsMonitorRunning).filter { it.scanner == "dns_monitor" }
}
