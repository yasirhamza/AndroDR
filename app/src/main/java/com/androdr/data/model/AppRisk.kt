package com.androdr.data.model

import kotlinx.serialization.Serializable

enum class RiskLevel(val score: Int) {
    CRITICAL(4),
    HIGH(3),
    MEDIUM(2),
    LOW(1)
}

@Serializable
data class AppRisk(
    val packageName: String,
    val appName: String,
    val riskLevel: RiskLevel,
    val reasons: List<String>,
    val isKnownMalware: Boolean,
    val isSideloaded: Boolean,
    val dangerousPermissions: List<String>
)
