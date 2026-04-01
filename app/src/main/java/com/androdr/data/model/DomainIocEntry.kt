package com.androdr.data.model

/** Feed DTO for domain IOC entries. Converted to [Indicator] by IndicatorUpdater. */
data class DomainIocEntry(
    val domain: String,
    val campaignName: String,
    val severity: String,
    val source: String,
    val fetchedAt: Long
)
