package com.androdr.scanner

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure
import com.androdr.ioc.FeedCoverage

/**
 * Sentinel entries for gaps in what a scan could see: no threat-intel feed rows yet (offline
 * first run, after the v19 table reset), one of the campaign-key sources missing (a failed or
 * unverified rules-repo fetch, the first refresh after the v19 drop), and the DNS tunnel being
 * off. None is a crash ([NotEvaluatedReason] sentinels are excluded from `realFailureCount`).
 * A missing campaign source shares the FEEDS_NOT_LOADED sentinel and heading; its message says
 * which source is missing. Per-campaign check state is follow-up #394.
 */
internal fun scanVisibilityGaps(coverage: FeedCoverage, dnsMonitorRunning: Boolean): List<ScannerFailure> = buildList {
    val missing = when {
        coverage.rows == 0 -> "threat-intel feeds not loaded yet"
        else -> listOfNotNull(
            if (coverage.rulesRepoLoaded) null
            else "AndroDR's own indicator list did not load, so the copy built into the app was checked instead",
            if (coverage.mvtLoaded) null
            else "the MVT spyware indicator lists did not load, so their campaign indicators were not checked",
        ).joinToString("; ").ifEmpty { null }
    }
    if (missing != null) {
        add(
            ScannerFailure(
                scanner = "threat_intel",
                exception = NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel,
                message = missing
            )
        )
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
