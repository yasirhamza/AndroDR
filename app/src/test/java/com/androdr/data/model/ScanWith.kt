package com.androdr.data.model

import com.androdr.sigma.Finding

/**
 * A scan with its [findings], built in memory for tests (schema 21 keeps findings out of
 * [ScanResult]); the summary columns are derived from [findings] as the writer derives them.
 */
@Suppress("LongParameterList")
fun scanWith(
    findings: List<Finding> = emptyList(),
    id: Long = 1L,
    timestamp: Long = id,
    bugReportFindings: List<String> = emptyList(),
    riskySideloadCount: Int = 0,
    knownMalwareCount: Int = 0,
    scannerErrors: List<ScannerFailure> = emptyList(),
    source: TelemetrySource = TelemetrySource.LIVE_SCAN,
    state: ScanState = ScanState.COMPLETE,
    telemetryState: TelemetryState = TelemetryState.NONE,
): ScanWithFindings = ScanWithFindings(
    ScanResult(
        id = id, timestamp = timestamp, bugReportFindings = bugReportFindings,
        riskySideloadCount = riskySideloadCount, knownMalwareCount = knownMalwareCount,
        scannerErrors = scannerErrors, source = source, state = state, telemetryState = telemetryState,
        triggeredCount = findings.count { it.triggered }, maxLevel = maxTriggeredLevel(findings),
    ),
    findings,
)
