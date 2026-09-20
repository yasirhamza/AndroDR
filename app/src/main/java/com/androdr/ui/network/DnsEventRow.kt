package com.androdr.ui.network

import com.androdr.data.model.DnsEvent
import com.androdr.network.DnsQueryAttribution

/** One line of the Network Monitor: the event, plus the text printed under the domain. */
data class DnsEventRow(val event: DnsEvent, val appLabel: String)

/** The packages on screen that need a display name; unattributed events need none. */
fun packagesNeedingLabels(events: List<DnsEvent>): Set<String> =
    events.mapNotNullTo(LinkedHashSet()) { it.appName }

/**
 * Builds the rows the screen renders.
 *
 * Kept out of the composable so the text under each domain is pinned by a unit
 * test: the screen once called the label helper with no display names, which
 * made the same event read differently on the screen and in the report.
 */
fun dnsEventRows(events: List<DnsEvent>, displayNames: Map<String, String>): List<DnsEventRow> =
    events.map { DnsEventRow(it, DnsQueryAttribution.label(it.appUid, it.appName, displayNames)) }
