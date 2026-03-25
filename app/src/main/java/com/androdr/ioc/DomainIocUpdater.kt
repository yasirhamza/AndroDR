package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.DomainIocEntryDao
import com.androdr.ioc.feeds.MvtIndicatorsFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Orchestrates all domain IOC feeds: runs them in parallel, upserts results into Room,
 * prunes stale entries, then refreshes [DomainIocResolver] so new data takes effect immediately.
 *
 * Mirrors [RemoteIocUpdater] for package-based IOCs.
 */
@Singleton
class DomainIocUpdater @Inject constructor(
    private val domainIocEntryDao: DomainIocEntryDao,
    private val domainIocResolver: DomainIocResolver,
    private val feeds: List<DomainIocFeed> = listOf(MvtIndicatorsFeed())
) {

    suspend fun update(): Int = withContext(Dispatchers.IO) {
        var totalStored = 0
        coroutineScope {
            val deferreds = feeds.map { feed ->
                async {
                    val entries = feed.fetch()
                    if (entries.isNotEmpty()) {
                        domainIocEntryDao.upsertAll(entries)
                        val runStart = entries.minOf { it.fetchedAt } - 1
                        domainIocEntryDao.deleteStaleEntries(feed.sourceId, runStart)
                        Log.i(TAG, "Domain feed '${feed.sourceId}': ${entries.size} entries upserted")
                    } else {
                        Log.w(TAG, "Domain feed '${feed.sourceId}': no entries returned")
                    }
                    entries.size
                }
            }
            totalStored = deferreds.sumOf { it.await() }
        }
        domainIocResolver.refreshCache()
        Log.i(TAG, "Domain update complete — fetched: $totalStored, DB: ${domainIocEntryDao.count()}")
        totalStored
    }

    companion object {
        private const val TAG = "DomainIocUpdater"
    }
}
