package com.androdr.data.model

import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory

/**
 * A scan with its findings: read from `scan_finding` through `FindingsRepository`, or, for a scan
 * that could not be saved, held in memory. The derived views of the findings live here, since
 * [ScanResult] no longer carries them (spec §5.4).
 */
data class ScanWithFindings(val scan: ScanResult, val findings: List<Finding>) {
    val id: Long get() = scan.id
    val timestamp: Long get() = scan.timestamp
    val source: TelemetrySource get() = scan.source
    val scannerErrors: List<ScannerFailure> get() = scan.scannerErrors
    val telemetryState: TelemetryState get() = scan.telemetryState
    val bugReportFindings: List<String> get() = scan.bugReportFindings
    val knownMalwareCount: Int get() = scan.knownMalwareCount
    val riskySideloadCount: Int get() = scan.riskySideloadCount
    val realFailureCount: Int get() = scan.realFailureCount
    val isPartialScan: Boolean get() = scan.isPartialScan
    val hasUnevaluatedRules: Boolean get() = scan.hasUnevaluatedRules

    /**
     * Overall risk is the highest severity among triggered findings -- nothing else.
     *
     * The incident-vs-condition distinction is the rule's `category:`, and it is
     * applied exactly once, by SeverityCapPolicy at finding creation: a posture
     * condition arrives here already clamped to medium, so it cannot out-shout an
     * incident. [Finding.category] is `display.category` -- which SECTION a finding
     * is shown in -- and is presentation only. Reading it here (#364) ceilinged any
     * incident that happened to be displayed under device posture: a critical
     * spyware artifact on disk (androdr-020) reported MEDIUM while the same report
     * listed it as CRITICAL, and low incidents shown under device posture
     * (androdr-072..076) were floored up to MEDIUM. Pinned by ScanResultOverallRiskTest.
     */
    val overallRiskLevel: RiskLevel
        get() = riskOf(findings.filter { it.triggered }.maxOfOrNull { levelToScore(it.level) } ?: 0)

    val deviceFlags: List<Finding>
        get() = findings.filter { it.category == FindingCategory.DEVICE_POSTURE }

    val appRisks: List<Finding>
        get() = findings.filter { it.category == FindingCategory.APP_RISK }

    /** Chains of events from the correlation engine -- "Warning signs that add up" to the reader (#350). */
    val activityChains: List<Finding>
        get() = findings.filter { it.category == FindingCategory.CORRELATION }
}

