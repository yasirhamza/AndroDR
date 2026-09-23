package com.androdr.reporting

import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.network.DnsQueryAttribution
import java.text.SimpleDateFormat
import java.util.Date

/**
 * The DNS ACTIVITY section, in its two forms.
 *
 * Which rows belong under that header depends on what the scan was: the tunnel's
 * own log for a live scan, the imported file's own queries for an import. Mixing
 * them put five hundred unrelated tunnel rows under an import's header (#375).
 * Kept beside the formatter rather than inside it so each form can be read, and
 * tested, on its own.
 */

/** Timeline categories a DNS query is recorded under, matched or not. */
private val DNS_CATEGORIES = setOf("dns_query", "ioc_match")
private const val MAX_DNS_ROWS = 500
private const val DOMAIN_COLUMN = 50

/** The tunnel's own log, for the scan that captured it. */
internal fun StringBuilder.appendLiveDns(
    dnsEvents: List<DnsEvent>,
    displayNames: Map<String, String>,
    dnsFmt: SimpleDateFormat,
) {
    if (dnsEvents.isEmpty()) {
        appendLine("  No DNS events recorded.")
        return
    }
    val matched = dnsEvents.count { it.reason != null }
    appendLine("  ${dnsEvents.size} events / $matched matched")
    appendLine()
    dnsEvents.take(MAX_DNS_ROWS).forEach { event ->
        val time = dnsFmt.format(Date(event.timestamp))
        val state = if (event.reason != null) "[MATCHED]" else "[ALLOWED]"
        val app = DnsQueryAttribution.label(event.appUid, event.appName, displayNames)
        appendLine("  $state  $time  ${event.domain.padEnd(DOMAIN_COLUMN)}  <- $app")
        if (event.reason != null) {
            appendLine("           reason: ${event.reason}")
        }
    }
}

/**
 * The DNS rows an import carried, attributed to the app that made each query.
 *
 * No allowed/matched verdict is printed here, unlike the live tunnel's rows: an
 * imported row has no block decision to report (the import parser records none),
 * so a `[ALLOWED]` stamp would say a threat-list domain was permitted when the
 * same report's FINDINGS section names it. What was detected in an import is in
 * FINDINGS; this section is the queries themselves.
 *
 * The rows are what this report embeds, not the import's whole log -- the import
 * in full is on the Timeline -- so nothing here claims a total.
 */
internal fun StringBuilder.appendImportedDns(
    intrusionEvents: List<ForensicTimelineEvent>,
    displayNames: Map<String, String>,
    dnsFmt: SimpleDateFormat,
) {
    val imported = intrusionEvents.filter { it.category in DNS_CATEGORIES }
    if (imported.isEmpty()) {
        appendLine("  No DNS rows from the import are included in this report.")
        appendLine("  The import's own log is on the Timeline; the live DNS monitor's")
        appendLine("  events belong to a different scan and are not shown here.")
        return
    }
    appendLine("  ${imported.size} DNS row(s) from the import, shown below.")
    appendLine("  (what this report embeds, not the import's whole log -- see the Timeline)")
    appendLine()
    imported.take(MAX_DNS_ROWS).forEach { event ->
        val time = dnsFmt.format(Date(event.startTimestamp))
        val app = DnsQueryAttribution.label(
            event.processUid, event.packageName.ifEmpty { null }, displayNames,
        )
        val domain = event.iocIndicator.ifEmpty { event.description.removePrefix("DNS: ") }
        appendLine("  $time  ${domain.padEnd(DOMAIN_COLUMN)}  <- $app")
    }
    if (imported.size > MAX_DNS_ROWS) {
        appendLine("  ... ${imported.size - MAX_DNS_ROWS} more row(s) not shown")
    }
}
