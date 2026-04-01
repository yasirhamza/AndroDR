package com.androdr.data.db

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TimelineEvent
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory

fun DnsEvent.toForensicTimelineEvent(): ForensicTimelineEvent = ForensicTimelineEvent(
    timestamp = this.timestamp,
    source = "dns_monitor",
    category = if (this.reason != null) "ioc_match" else "dns_query",
    description = "DNS: ${this.domain}" +
        (this.reason?.let { " [MATCHED: $it]" } ?: ""),
    severity = if (this.reason != null) "HIGH" else "INFO",
    packageName = this.appName ?: "",
    processUid = this.appUid,
    iocIndicator = if (this.reason != null) this.domain else "",
    iocType = if (this.reason != null) "domain" else "",
    iocSource = if (this.reason != null) extractDnsIocSource(this.reason) else "",
    campaignName = if (this.reason != null) extractDnsCampaign(this.reason) else "",
    isFromRuntime = true
)

fun Finding.toForensicTimelineEvent(scanResult: ScanResult): ForensicTimelineEvent {
    val iocEvidence = this.evidence as? Evidence.IocMatch
    val campaignTag = this.tags.filter { it.startsWith("campaign.") }
        .joinToString(" / ") { it.removePrefix("campaign.").replaceFirstChar { c -> c.uppercase() } }
        .ifEmpty { null }

    return ForensicTimelineEvent(
        timestamp = scanResult.timestamp,
        source = "app_scanner",
        category = when (this.category) {
            FindingCategory.APP_RISK -> "app_risk"
            FindingCategory.DEVICE_POSTURE -> "device_posture"
            FindingCategory.NETWORK -> "network_anomaly"
        },
        description = this.title,
        details = this.description,
        severity = this.level.uppercase(),
        packageName = this.matchContext["package_name"] ?: "",
        appName = this.matchContext["app_name"] ?: "",
        apkHash = this.matchContext["apk_hash"] ?: "",
        iocIndicator = iocEvidence?.matchedIndicator ?: "",
        iocType = iocEvidence?.iocType ?: "",
        iocSource = iocEvidence?.source ?: "",
        campaignName = campaignTag ?: "",
        ruleId = this.ruleId,
        scanResultId = scanResult.id,
        attackTechniqueId = this.tags.firstOrNull { it.startsWith("attack.t") }
            ?.removePrefix("attack.") ?: "",
        isFromRuntime = true
    )
}

fun TimelineEvent.toForensicTimelineEvent(scanResultId: Long = -1): ForensicTimelineEvent =
    ForensicTimelineEvent(
        timestamp = this.timestamp,
        source = this.source,
        category = this.category,
        description = this.description,
        severity = this.severity,
        timestampPrecision = "estimated",
        scanResultId = scanResultId,
        isFromBugreport = true
    )

/** Extracts the campaign name from DNS event reason strings like "IOC: Pegasus" */
private fun extractDnsCampaign(reason: String?): String = when {
    reason == null -> ""
    reason.startsWith("IOC: ") -> reason.removePrefix("IOC: ")
    reason.startsWith("IOC_detect: ") -> reason.removePrefix("IOC_detect: ")
    else -> ""
}

/** Extracts the feed source from DNS event reason strings like "IOC: Pegasus" */
private fun extractDnsIocSource(reason: String?): String = when {
    reason == null -> ""
    reason.startsWith("IOC:") || reason.startsWith("IOC_detect:") -> "domain_ioc_feed"
    reason == "blocklist" || reason == "blocklist_detect" -> "blocklist"
    else -> ""
}
