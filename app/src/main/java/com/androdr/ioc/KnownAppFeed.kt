package com.androdr.ioc

import com.androdr.data.model.KnownAppEntry

interface KnownAppFeed {
    val sourceId: String
    /** Returns all entries from this feed, or an empty list on any failure. */
    suspend fun fetch(): List<KnownAppEntry>
}
