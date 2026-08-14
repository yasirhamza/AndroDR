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
 *
 * @property ruleId The SIGMA rule this entry is about, for the entries where
 *   that is meaningful — today only capability skips
 *   ([UNREGISTERED_IOC_LOOKUP]), which name exactly one rule each. Null for
 *   scanner crashes (a crashed scanner is not attributable to one rule) and
 *   for capability-skip rows persisted before this field existed. Structured
 *   here rather than parsed back out of [message] so consumers
 *   ([com.androdr.scanner.ScanOrchestrator.computeDiff]) never depend on the
 *   message wording.
 *
 * The column is a kotlinx-serialized JSON TEXT blob (see
 * [com.androdr.data.db.Converters.fromScannerFailureList]), so adding this
 * field needs NO Room migration: rows written before it existed simply
 * deserialize with the default. The converter's `Json` is configured
 * `ignoreUnknownKeys = true` and is not `explicitNulls`/strict about absent
 * optional fields, so an old row (no `ruleId` key at all) decodes to null.
 */
@Serializable
data class ScannerFailure(
    val scanner: String,
    val exception: String,
    val message: String?,
    val ruleId: String? = null
)

/**
 * [ScannerFailure.exception] value marking a capability skip — a rule this
 * binary build cannot evaluate (unresolvable ioc_lookup) — as opposed to a
 * scanner crash. A capability skip is accepted under-detection, not a
 * failure: it must not raise the partial-scan banner (see [ScanResult.isPartialScan]).
 */
const val UNREGISTERED_IOC_LOOKUP = "UnregisteredIocLookup"

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
     * Scanner-level entries recorded during this scan. Two kinds live here:
     * real scanner failures (a scanner threw — the scan is partial and the
     * final findings may be missing categories) and capability skips
     * ([UNREGISTERED_IOC_LOOKUP] — a rule this binary cannot evaluate, which
     * is accepted under-detection, not a failure). A non-empty list therefore
     * does NOT imply a partial scan: use [isPartialScan] / [realFailureCount],
     * never `scannerErrors.isNotEmpty()`.
     *
     * Default empty for backward compatibility with data persisted before the
     * column existed (see MIGRATION_10_11 — old rows are populated with `[]`).
     */
    val scannerErrors: List<ScannerFailure> = emptyList()
) {
    /**
     * Number of entries in [scannerErrors] that are real scanner failures —
     * capability skips ([UNREGISTERED_IOC_LOOKUP]) excluded. The single
     * definition of "how many scanners actually failed", so the partial-scan
     * banner's count and [isPartialScan] can never disagree.
     */
    @get:Ignore
    @Transient
    val realFailureCount: Int
        get() = scannerErrors.count { it.exception != UNREGISTERED_IOC_LOOKUP }

    /**
     * True if any scanner failed to complete during this scan. Capability
     * skips ([UNREGISTERED_IOC_LOOKUP]) are excluded — a rule this binary
     * cannot evaluate is accepted under-detection, not a failed scanner,
     * and must not raise the partial-scan banner.
     */
    @get:Ignore
    @Transient
    val isPartialScan: Boolean
        get() = realFailureCount > 0

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
