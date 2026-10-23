package com.androdr.reporting

import com.androdr.data.model.ScanWithFindings
import com.androdr.sigma.Evidence

/** Report lines that name the threat-list entry a finding matched. Beside the formatter, as DnsReportSection is. */

/** "forti.external-muki.com -> Graphite (Paragon) (NATION_STATE_SPYWARE)", or the bare indicator. */
internal fun iocMatchLabel(e: Evidence.IocMatch): String = buildString {
    append(e.matchedIndicator)
    if (e.family.isNotBlank()) {
        append(" -> ").append(e.family)
        if (e.category.isNotBlank()) append(" (").append(e.category).append(")")
    }
}

/**
 * Whether the tunnel blocked the domain, from the DNS event's reason. An absent reason is the
 * cold-start case: the rule matched at scan time but the tunnel saw no list entry
 * (SigmaRuleEvaluator maps a null record value to ""). Null for a reason we do not recognise.
 */
internal fun blockedText(reason: String?): String? = when {
    reason.isNullOrEmpty() ->
        "no (not checked by the tunnel: the threat list was not loaded when queried; matched at scan time)"
    reason.startsWith("IOC_detect:") -> "no (blocking is off for threat-list domains)"
    reason.startsWith("IOC:") || reason == "blocklist" -> "yes"
    reason == "blocklist_detect" -> "no (blocklist blocking is off)"
    else -> null
}

/** Domains the scan's findings matched against the threat lists. */
internal fun iocDomainsOf(scan: ScanWithFindings): Set<String> =
    scan.appRisks.mapNotNull { it.evidence as? Evidence.IocMatch }
        .filter { it.iocType == "domain" }.map { it.matchedIndicator }.toSet()

/**
 * The rows of "DNS IOC matches linked to:": distinct domains from the scan's domain IOC
 * findings, else (scans whose findings carry no IOC evidence) the `reason` strings of this scan's own
 * stored DNS records.
 * The summary count and the list both come from here so they cannot disagree.
 */
internal fun dnsIocRows(scan: ScanWithFindings, dnsReasons: Collection<String>): List<String> {
    val fromEvidence = scan.appRisks.filter { it.triggered }
        .mapNotNull { it.evidence as? Evidence.IocMatch }
        .filter { it.iocType == "domain" }
        .map { iocMatchLabel(it) }
        .distinct()
    return fromEvidence.ifEmpty {
        dnsReasons
            .asSequence()
            .filter { it.startsWith("IOC:") || it.startsWith("IOC_detect:") }
            .map { it.removePrefix("IOC:").removePrefix("IOC_detect:").trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .map { "$it (domain indicator)" }
            .toList()
    }
}

/** "DNS IOC matches linked to:", in its own block so a domain hit with no campaign flag is listed. */
internal fun ReportOut.appendDnsIocMatches(rows: List<String>) {
    if (rows.isEmpty()) return
    appendLine("  DNS IOC matches linked to:")
    rows.forEach { appendLine("  [!!]  $it") }
    appendLine()
}
