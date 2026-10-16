package com.androdr.scanner

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure

/**
 * Sentinel entries for gaps in what a scan could see: no threat-intel feed rows yet (offline
 * first run, after the v19 table reset) and the DNS tunnel being off. Neither is a crash
 * ([NotEvaluatedReason] sentinels are excluded from `realFailureCount`).
 */
internal fun scanVisibilityGaps(indicatorRows: Int, dnsMonitorRunning: Boolean): List<ScannerFailure> = buildList {
    if (indicatorRows == 0) {
        add(
            ScannerFailure(
                scanner = "threat_intel",
                exception = NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel,
                message = "threat-intel feeds not loaded yet"
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
 * [scanVisibilityGaps] for a live scan, tolerating a failing row count: the state is then
 * unknown, so neither not-checked entry is claimed and one real failure is recorded instead.
 * The count is a plain DAO call that used to run unguarded ahead of every scanner.
 */
@Suppress("TooGenericExceptionCaught")
internal suspend fun visibilityGapsOrFailure(
    countRows: suspend () -> Int,
    dnsMonitorRunning: Boolean,
): List<ScannerFailure> = try {
    scanVisibilityGaps(countRows(), dnsMonitorRunning)
} catch (c: kotlinx.coroutines.CancellationException) {
    throw c
} catch (e: Exception) {
    listOf(
        ScannerFailure(
            scanner = "visibility_gaps",
            exception = e::class.simpleName ?: "Exception",
            message = "could not tell whether threat-intel feeds are loaded"
        )
    ) + scanVisibilityGaps(1, dnsMonitorRunning).filter { it.scanner == "dns_monitor" }
}
