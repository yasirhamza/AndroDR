package com.androdr.data.model

import androidx.room.Entity

/**
 * Unified threat indicator entity. Replaces the per-type IOC tables
 * (ioc_entries, domain_ioc_entries, cert_hash_ioc_entries) with a single
 * table discriminated by [type].
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
    val name: String = "",      // display name / family name
    val campaign: String = "",  // campaign / threat actor attribution
    val severity: String = "HIGH",
    val description: String = "",
    val source: String,         // feed source ID
    val fetchedAt: Long
)
