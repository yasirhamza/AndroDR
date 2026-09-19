// app/src/main/java/com/androdr/sigma/Evidence.kt
package com.androdr.sigma

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The report/UI SECTION a finding is shown in. Presentation only -- never an input
 * to severity or overall risk (see ScanResult.overallRiskLevel).
 *
 * Must equal the `display.category` enum in the rule schema exactly, and every
 * value must have a renderer: DisplayCategoryCrossCheckTest and
 * ReportRendersEveryFindingCategoryTest fail the build otherwise. `NETWORK` was
 * removed for having neither a rule nor a renderer (#367).
 */
enum class FindingCategory {
    DEVICE_POSTURE,
    APP_RISK,

    /**
     * A chain of events from the correlation engine (#350). Internal name only --
     * people see it as "suspicious activity chains" (ReportFormatter.CHAINS_SECTION).
     */
    CORRELATION
}

@Serializable
sealed interface Evidence {
    @Serializable
    @SerialName("none")
    data object None : Evidence

    @Serializable
    @SerialName("cve_list")
    data class CveList(
        val cves: List<CveEvidence>,
        val targetPatchLevel: String,
        val campaignCount: Int
    ) : Evidence

    @Serializable
    @SerialName("ioc_match")
    data class IocMatch(
        val matchedIndicator: String,
        val iocType: String,
        val source: String
    ) : Evidence

    @Serializable
    @SerialName("permission_cluster")
    data class PermissionCluster(
        val permissions: List<String>,
        val surveillanceCount: Int
    ) : Evidence
}

@Serializable
data class CveEvidence(
    val cveId: String,
    val description: String,
    val severity: String,
    val patchLevel: String,
    val campaigns: List<String>,
    val dateAdded: String
)
