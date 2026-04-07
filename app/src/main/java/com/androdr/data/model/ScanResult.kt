package com.androdr.data.model

import androidx.room.Entity
import androidx.room.Ignore
import androidx.room.PrimaryKey
import androidx.room.TypeConverters
import com.androdr.data.db.Converters
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Records a scanner-level failure during a scan. The scanner collection phase
 * catches exceptions per-scanner and records them here rather than letting them
 * abort the whole scan, but the failures are preserved so the UI can tell the
 * user "this scan was incomplete" instead of silently reporting "no threats".
 *
 * This exists because silently swallowing scanner exceptions turns
 * crash-on-inspection into a detection-evasion technique: a malware sample
 * that crashes one scanner would otherwise cause that scanner's findings to
 * disappear entirely, indistinguishable from a clean result.
 */
@Serializable
data class ScannerFailure(
    val scanner: String,
    val exception: String,
    val message: String?
)

@Entity
@Serializable
@TypeConverters(Converters::class)
data class ScanResult(
    @PrimaryKey
    val id: Long = System.currentTimeMillis(),
    val timestamp: Long,
    val findings: List<Finding>,
    val bugReportFindings: List<String>,
    val riskySideloadCount: Int,
    val knownMalwareCount: Int,
    /**
     * Scanner-level failures recorded during this scan. An empty list means
     * every scanner completed successfully; a non-empty list means the scan
     * was partial and the final findings may be missing categories.
     *
     * Default empty for backward compatibility with data persisted before the
     * column existed (see MIGRATION_10_11 — old rows are populated with `[]`).
     */
    val scannerErrors: List<ScannerFailure> = emptyList()
) {
    /** True if any scanner failed to complete during this scan. */
    @get:Ignore
    @Transient
    val isPartialScan: Boolean
        get() = scannerErrors.isNotEmpty()

    // Overall risk driven by app threats. Device posture is a condition (not an incident)
    // and caps at MEDIUM. NETWORK findings are included with APP_RISK since DNS IOC rules
    // (androdr-003) use app_risk category; if future NETWORK-category rules are added,
    // include them here.
    @get:Ignore
    @Transient
    val overallRiskLevel: RiskLevel
        get() {
            val appMax = findings
                .filter { it.triggered && it.category != FindingCategory.DEVICE_POSTURE }
                .maxOfOrNull { levelToScore(it.level) } ?: 0
            val hasDeviceIssues = findings
                .any { it.triggered && it.category == FindingCategory.DEVICE_POSTURE }
            return when {
                appMax >= RiskLevel.CRITICAL.score -> RiskLevel.CRITICAL
                appMax >= RiskLevel.HIGH.score -> RiskLevel.HIGH
                appMax >= RiskLevel.MEDIUM.score || hasDeviceIssues -> RiskLevel.MEDIUM
                else -> RiskLevel.LOW
            }
        }

    @get:Ignore
    @Transient
    val deviceFlags: List<Finding>
        get() = findings.filter { it.category == FindingCategory.DEVICE_POSTURE }

    @get:Ignore
    @Transient
    val appRisks: List<Finding>
        get() = findings.filter { it.category == FindingCategory.APP_RISK }
}

private fun levelToScore(level: String): Int = when (level.lowercase()) {
    "critical" -> RiskLevel.CRITICAL.score
    "high" -> RiskLevel.HIGH.score
    "medium" -> RiskLevel.MEDIUM.score
    else -> RiskLevel.LOW.score
}
