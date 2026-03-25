package com.androdr.ioc

import com.androdr.data.model.DomainIocEntry

/**
 * Common interface for domain-based IOC feed adapters.
 * Mirrors [IocFeed]; return an empty list on any failure (never throw).
 */
interface DomainIocFeed {
    val sourceId: String
    suspend fun fetch(): List<DomainIocEntry>
}
