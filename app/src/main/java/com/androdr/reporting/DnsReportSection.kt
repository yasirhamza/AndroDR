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
 * The DNS an imported file carried, attributed to the app that made each query.
 * The embedded sample is capped; the Timeline holds the import in full.
 */
internal fun StringBuilder.appendImportedDns(
    intrusionEvents: List<ForensicTimelineEvent>,
    displayNames: Map<String, String>,
    dnsFmt: SimpleDateFormat,
) {
    val imported = intrusionEvents.filter { it.category in DNS_CATEGORIES }
    if (imported.isEmpty()) {
        appendLine("  This scan analysed an imported file, which carried no DNS log.")
        appendLine("  The live DNS monitor's own events belong to a different scan; see the Timeline.")
        return
    }
    val matched = imported.count { it.category == "ioc_match" }
    appendLine("  ${imported.size} event(s) from the import / $matched matched")
    appendLine("  (sample embedded in this report; the import in full is on the Timeline)")
    appendLine()
    imported.forEach { event ->
        val time = dnsFmt.format(Date(event.startTimestamp))
        val state = if (event.category == "ioc_match") "[MATCHED]" else "[ALLOWED]"
        val app = DnsQueryAttribution.label(
            event.processUid, event.packageName.ifEmpty { null }, displayNames,
        )
        val domain = event.description.removePrefix("DNS: ")
        appendLine("  $state  $time  ${domain.padEnd(DOMAIN_COLUMN)}  <- $app")
    }
}
