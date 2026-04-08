package com.androdr.data.db

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TimelineEvent
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory

fun DnsEvent.toForensicTimelineEvent(): ForensicTimelineEvent =
    toForensicTimelineEvent(indicator = null)

/**
 * Overload that takes the enriched [Indicator] row looked up by
 * `ScanRepository.logDnsEventsBatch` off the VPN hot path. When the indicator
 * carries a real campaign name (as opposed to the VPN bloom filter's empty
 * stub), the timeline row's `campaignName`, `severity`, and `iocSource` are
 * populated from the indicator metadata instead of the raw reason string.
 */
fun DnsEvent.toForensicTimelineEvent(indicator: com.androdr.data.model.Indicator?): ForensicTimelineEvent {
    val isMatched = this.reason != null
    val realCampaign = indicator?.campaign?.takeIf { it.isNotBlank() }
    val realSeverity = indicator?.severity?.takeIf { it.isNotBlank() && it.uppercase() != "UNKNOWN" }
    val realSource = indicator?.source?.takeIf { it.isNotBlank() }
    val realDescription = indicator?.description?.takeIf { it.isNotBlank() }
    return ForensicTimelineEvent(
        startTimestamp = this.timestamp,
        source = "dns_monitor",
        category = if (isMatched) "ioc_match" else "dns_query",
        description = "DNS: ${this.domain}" +
            (if (isMatched && realCampaign != null) " [$realCampaign]"
             else this.reason?.let { " [MATCHED: $it]" } ?: ""),
        details = realDescription ?: "",
        severity = when {
            !isMatched -> "INFO"
            realSeverity != null -> realSeverity.uppercase()
            else -> "HIGH"
        },
        packageName = this.appName ?: "",
        processUid = this.appUid,
        iocIndicator = if (isMatched) this.domain else "",
        iocType = if (isMatched) "domain" else "",
        iocSource = when {
            !isMatched -> ""
            realSource != null -> realSource
            else -> extractDnsIocSource(this.reason)
        },
        campaignName = when {
            !isMatched -> ""
            realCampaign != null -> realCampaign
            else -> extractDnsCampaign(this.reason)
        },
        isFromRuntime = true
    )
}

fun Finding.toForensicTimelineEvent(
    scanResult: ScanResult,
    isBugreport: Boolean = false
): ForensicTimelineEvent {
    val iocEvidence = this.evidence as? Evidence.IocMatch
    val campaignTag = this.tags.filter { it.startsWith("campaign.") }
        .joinToString(" / ") { it.removePrefix("campaign.").replaceFirstChar { c -> c.uppercase() } }
        .ifEmpty { null }

    // Runtime-scan findings use the scan timestamp. Bug-report findings try
    // to inherit a real per-event timestamp from their evidence:
    //
    //   * Modules that know a real event time (e.g. `AppOpsModule` knows
    //     `last_access_time` for each dangerous-op record) publish it under
    //     the telemetry map key `event_time_ms` (epoch ms Long).
    //   * `SigmaRuleEvaluator.buildFinding` copies scalar record fields
    //     into `matchContext` as strings, so the Finding inherits the
    //     `event_time_ms` string automatically.
    //   * Here we parse it back to a Long and use it as the persisted
    //     event's `timestamp`. If it's missing or unparseable, we fall
    //     back to 0L, which the Timeline UI renders as "Unknown" — the
    //     honest answer for SIGMA rules that fire on stateful data
    //     without a meaningful event time (e.g. receiver registrations).
    //
    // This is strictly better than the previous unconditional 0L for bug
    // reports: AppOps-derived findings (Camera Access, Microphone Access,
    // etc.) now show the real time the dangerous op was last invoked,
    // instead of "Unknown".
    val eventTimestamp = if (isBugreport) {
        this.matchContext["event_time_ms"]?.toLongOrNull()?.takeIf { it > 0L } ?: 0L
    } else {
        scanResult.timestamp
    }

    return ForensicTimelineEvent(
        startTimestamp = eventTimestamp,
        source = if (isBugreport) "bugreport_analysis" else "app_scanner",
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
        isFromBugreport = isBugreport,
        isFromRuntime = !isBugreport
    )
}

fun TimelineEvent.toForensicTimelineEvent(scanResultId: Long = -1): ForensicTimelineEvent =
    ForensicTimelineEvent(
        startTimestamp = this.timestamp,
        source = this.source,
        category = this.category,
        description = this.description,
        severity = this.severity,
        packageName = this.packageName ?: "",
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
