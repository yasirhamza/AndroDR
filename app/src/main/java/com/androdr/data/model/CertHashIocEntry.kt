package com.androdr.data.model

/** Feed DTO for cert hash IOC entries. Converted to [Indicator] by IndicatorUpdater. */
data class CertHashIocEntry(
    val certHash: String,
    val familyName: String,
    val category: String,
    val severity: String,
    val description: String,
    val source: String,
    val fetchedAt: Long
)
