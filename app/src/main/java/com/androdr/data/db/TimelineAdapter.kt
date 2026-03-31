package com.androdr.data.db

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TimelineEvent
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
    isFromRuntime = true
)

fun Finding.toForensicTimelineEvent(scanResult: ScanResult): ForensicTimelineEvent =
    ForensicTimelineEvent(
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
        apkHash = this.matchContext["apk_hash"] ?: "",
        ruleId = this.ruleId,
        scanResultId = scanResult.id,
        attackTechniqueId = this.tags.firstOrNull { it.startsWith("attack.t") }
            ?.removePrefix("attack.") ?: "",
        isFromRuntime = true
    )

fun TimelineEvent.toForensicTimelineEvent(scanResultId: Long = -1): ForensicTimelineEvent =
    ForensicTimelineEvent(
        timestamp = this.timestamp,
        source = this.source,
        category = this.category,
        description = this.description,
        severity = this.severity,
        scanResultId = scanResultId,
        isFromBugreport = true
    )
