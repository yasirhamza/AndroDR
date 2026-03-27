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
    val knownMalwareCount: Int
) {
    @get:Ignore
    @Transient
    val overallRiskLevel: RiskLevel
        get() {
            val maxLevel = findings
                .filter { it.triggered }
                .maxOfOrNull { levelToScore(it.level) } ?: 0
            return when {
                maxLevel >= RiskLevel.CRITICAL.score -> RiskLevel.CRITICAL
                maxLevel >= RiskLevel.HIGH.score -> RiskLevel.HIGH
                maxLevel >= RiskLevel.MEDIUM.score -> RiskLevel.MEDIUM
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
