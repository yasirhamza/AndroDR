package com.androdr.ioc

import com.androdr.data.model.IocEntry

/**
 * Common interface for remote IOC feed adapters.
 *
 * Each implementation is responsible for fetching entries from one source,
 * normalising them into [IocEntry] objects, and returning an empty list on
 * any network or parsing failure.
 */
interface IocFeed {
    /** Unique identifier stored as [IocEntry.source] for all entries this feed produces. */
    val sourceId: String

    /**
     * Fetches and normalises IOC entries from the remote source.
     * Must not throw — return an empty list on failure.
     */
    suspend fun fetch(): List<IocEntry>
}
