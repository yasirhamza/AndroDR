package com.androdr.data.model

import androidx.room.Entity

/**
 * Unified threat indicator entity. Replaces the per-type IOC tables
 * (ioc_entries, domain_ioc_entries, cert_hash_ioc_entries) with a single
 * table discriminated by [type].
 *
 * One layout for every [type] (schema 19): [family] is the label a finding
 * names, [category] the threat category (or "" when the feed has none),
 * [campaignKey] the campaign key (pegasus, predator, graphite, ...) or "",
 * and [reference] a `https://` URL or `feed:<id>#<record>` (or "" when it is
 * derivable from [source] and [family]).
 *
 * Known-good apps and CVEs remain in separate tables — they serve
 * different purposes (allowlisting and vulnerability metadata).
 */
@Entity(
    tableName = "indicators",
    primaryKeys = ["type", "value"]
)
data class Indicator(
    val type: String,           // "package", "domain", "cert_hash", "apk_hash"
    val value: String,          // the match value (package name, domain, hash)
    val family: String = "",      // family / campaign label a finding names
    val category: String = "",    // threat category, or "" when the feed has none
    val campaignKey: String = "", // campaign key (pegasus, predator, graphite, ...) or ""
    val severity: String = "HIGH",
    val description: String = "",
    val source: String,         // feed source ID
    val reference: String = "",   // https://... or feed:<id>#<record>
    val fetchedAt: Long
)
