package com.androdr.data.db

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.TAXONOMY_CONTRACT_TABLE

fun DnsEvent.toForensicTimelineEvent(): ForensicTimelineEvent =
    toForensicTimelineEvent(indicator = null)

/**
 * Overload that takes the enriched [Indicator] row looked up by
 * `ScanRepository.logDnsEventsBatch` off the VPN hot path. When the indicator
 * carries a real campaign name (as opposed to the VPN bloom filter's empty
 * stub), the timeline row's `campaignName`, `severity`, and `iocSource` are
 * populated from the indicator metadata instead of the raw reason string.
 */
fun DnsEvent.toForensicTimelineEvent(
    indicator: com.androdr.data.model.Indicator?,
    sourceEventKey: ByteArray? = null,
): ForensicTimelineEvent {
    val isMatched = this.reason != null
    val realCampaign = indicator?.family?.takeIf { it.isNotBlank() }
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
        // Linkage key for the Timeline UI to associate this DNS event with
        // any SIGMA finding fired by the DNS-scan path on the same domain.
        // Matches the correlationId stamped on Finding rows in
        // Finding.toForensicTimelineEvent when matchContext["domain"] is set.
        correlationId = if (isMatched) "dns:${this.domain}" else "",
        // h128 of the stored live DNS fact's source key ("dns:$id"), so the row joins its fact (J1).
        sourceEventKey = sourceEventKey,
        telemetrySource = com.androdr.data.model.TelemetrySource.LIVE_SCAN
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

    // DNS-sourced findings (rules with logsource.service = dns_monitor and
    // selection `domain|ioc_lookup: domain_ioc_db`) don't produce an
    // Evidence.IocMatch instance — they match via the ioc_lookup modifier
    // which only sets matchContext["domain"] to the queried hostname.
    // Without this fallback, the persisted row lost the matched domain
    // entirely: iocIndicator was blank, there was no way for the Timeline
    // UI to show "which domain triggered the Graphite/Paragon finding",
    // and multiple matches on the same scan rendered as indistinguishable
    // duplicate cards. Pull matchContext.domain as a last-resort IOC.
    val dnsMatchedDomain = this.matchContext["domain"]?.takeIf { it.isNotBlank() }
    val dnsIndicator = iocEvidence?.matchedIndicator ?: dnsMatchedDomain ?: ""
    val dnsIocType = iocEvidence?.iocType ?: (if (dnsMatchedDomain != null) "domain" else "")
    val dnsIocSource = iocEvidence?.source ?: (if (dnsMatchedDomain != null) "dns_monitor" else "")

    // Runtime-scan findings use the scan timestamp. Import findings inherit the event time of the
    // record they matched (FindingEventTime), with its precision; a finding on a record with no
    // event time (a snapshot) stays at 0L, which the Timeline renders as "Unknown date".
    val recorded = if (isBugreport) FindingEventTime.of(this) else null
    val eventTimestamp = if (isBugreport) recorded?.time ?: 0L else scanResult.timestamp

    return ForensicTimelineEvent(
        startTimestamp = eventTimestamp,
        timestampPrecision = if (recorded?.day == true) DAY_PRECISION else EXACT_PRECISION,
        source = if (isBugreport) "bugreport_analysis" else "app_scanner",
        category = when (this.category) {
            FindingCategory.APP_RISK -> "app_risk"
            FindingCategory.DEVICE_POSTURE -> "device_posture"
            FindingCategory.CORRELATION -> "correlation"
        },
        // For DNS findings, append the matched domain to the title so the
        // Timeline card shows "Graphite/Paragon Spyware: 0-38.com" instead
        // of 3 indistinguishable "Graphite/Paragon Spyware" rows.
        description = if (dnsMatchedDomain != null) "${this.title}: $dnsMatchedDomain" else this.title,
        details = this.description,
        packageName = this.matchContext["package_name"] ?: "",
        appName = this.matchContext["app_name"] ?: "",
        apkHash = this.matchContext["apk_hash"] ?: "",
        iocIndicator = dnsIndicator,
        iocType = dnsIocType,
        iocSource = dnsIocSource,
        campaignName = iocEvidence?.family?.takeIf { it.isNotBlank() } ?: campaignTag ?: "",
        // For DNS findings, use the matched domain as a linkage key. The
        // Timeline UI can join on correlationId to find the underlying
        // ioc_match row (which has iocIndicator = same domain). This gives
        // users a jump-to-evidence path without a schema change.
        correlationId = if (dnsMatchedDomain != null) "dns:$dnsMatchedDomain" else "",
        ruleId = this.ruleId,
        scanResultId = scanResult.id,
        level = this.level,
        attackTechniqueId = this.tags.firstOrNull { it.startsWith("attack.t") }
            ?.removePrefix("attack.") ?: "",
        telemetrySource = if (isBugreport) {
            com.androdr.data.model.TelemetrySource.BUGREPORT_IMPORT
        } else {
            com.androdr.data.model.TelemetrySource.LIVE_SCAN
        }
    )
}

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

private const val DAY_PRECISION = "day"
private const val EXACT_PRECISION = "exact"

/**
 * The event time a finding inherits from the record it matched (C4 review n1).
 * `SigmaRuleEvaluator.buildFinding` copies a record's scalar fields into `matchContext` as strings,
 * so the record's event-time field is there under its taxonomy name: `event_time_ms` (AppOps),
 * `timestamp` (battery days, security log, DNS, connections, usage, install history),
 * `crash_timestamp`, `acquired_at`. [FIELDS] is every service's event-time field, read from the
 * taxonomy (so a new service is covered); only event services carry these names. A day-precision
 * record's time is its calendar date ([com.androdr.data.model.CivilDay], R32).
 */
internal object FindingEventTime {
    data class Time(val time: Long, val day: Boolean)

    val FIELDS: List<String> = TAXONOMY_CONTRACT_TABLE.values.mapNotNull { it.eventTimeField }.distinct()
    val PRECISION_FIELDS: List<String> = TAXONOMY_CONTRACT_TABLE.values.mapNotNull { it.precisionField }.distinct()

    fun of(finding: Finding): Time? {
        val time = FIELDS.firstNotNullOfOrNull { finding.matchContext[it]?.toLongOrNull()?.takeIf { t -> t > 0L } }
            ?: return null
        val day = PRECISION_FIELDS.any { finding.matchContext[it].equals(DAY_PRECISION, ignoreCase = true) }
        return Time(time, day)
    }
}
