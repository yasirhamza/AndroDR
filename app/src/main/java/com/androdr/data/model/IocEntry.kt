package com.androdr.data.model

/** Feed DTO for package-name IOC entries. Converted to [Indicator] by IndicatorUpdater. */
data class IocEntry(
    val packageName: String,
    val name: String,
    val category: String,
    val severity: String,
    val description: String,
    val source: String,
    val fetchedAt: Long
)
