package com.androdr.data.model

import androidx.room.Entity
import androidx.room.Ignore
import androidx.room.PrimaryKey
import androidx.room.TypeConverters
import com.androdr.data.db.Converters
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Entity
@Serializable
@TypeConverters(Converters::class)
data class ScanResult(
    @PrimaryKey
    val id: Long = System.currentTimeMillis(),
    val timestamp: Long,
    val appRisks: List<AppRisk>,
    val deviceFlags: List<DeviceFlag>,
    val bugReportFindings: List<String>,
    val riskySideloadCount: Int,
    val knownMalwareCount: Int
) {
    @get:Ignore
    @Transient
    val overallRiskLevel: RiskLevel
        get() {
            val appMax = appRisks.maxOfOrNull { it.riskLevel.score }
            val flagMax = deviceFlags
                .filter { it.isTriggered }
                .maxOfOrNull { it.severity.toRiskScore() }
            val maxScore = maxOf(appMax ?: 0, flagMax ?: 0)
            return when {
                maxScore >= RiskLevel.CRITICAL.score -> RiskLevel.CRITICAL
                maxScore >= RiskLevel.HIGH.score     -> RiskLevel.HIGH
                maxScore >= RiskLevel.MEDIUM.score   -> RiskLevel.MEDIUM
                else                                 -> RiskLevel.LOW
            }
        }
}

private fun Severity.toRiskScore(): Int = when (this) {
    Severity.CRITICAL -> RiskLevel.CRITICAL.score
    Severity.HIGH     -> RiskLevel.HIGH.score
    Severity.MEDIUM   -> RiskLevel.MEDIUM.score
    Severity.INFO     -> RiskLevel.LOW.score
}
