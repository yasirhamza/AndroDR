package com.androdr.ioc

import com.androdr.data.db.DomainIocEntryDao
import com.androdr.data.model.DomainIocEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * In-memory lookup for domain-based IOC entries fetched from remote MVT feeds.
 *
 * Performs the same label-stripping hierarchy walk as [com.androdr.network.BlocklistManager]
 * so that a query for "c2.evil.com" matches an entry keyed on "evil.com".
 *
 * Call [refreshCache] after each [DomainIocUpdater] run and on app startup.
 */
@Singleton
class DomainIocResolver @Inject constructor(
    private val dao: DomainIocEntryDao
) {
    private val cache = AtomicReference<Map<String, DomainIocEntry>?>(null)

    /** Reloads all domain IOC rows from Room into the in-memory cache. */
    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        val map = buildMap<String, DomainIocEntry> {
            dao.getAll().forEach { entry -> put(entry.domain, entry) }
        }
        cache.set(map)
    }

    /**
     * Returns the [DomainIocEntry] whose domain matches [domain] or any of its parent domains,
     * or `null` if no match is found or the cache has not yet been loaded.
     */
    @Suppress("ReturnCount") // Label-stripping walk uses early returns identical to BlocklistManager
    fun isKnownBadDomain(domain: String): DomainIocEntry? {
        val snapshot = cache.get() ?: return null
        if (domain.isBlank()) return null

        var candidate = domain.trimEnd('.').lowercase()
        while (candidate.isNotEmpty()) {
            snapshot[candidate]?.let { return it }
            val dot = candidate.indexOf('.')
            if (dot < 0) break
            candidate = candidate.substring(dot + 1)
        }
        return null
    }
}
