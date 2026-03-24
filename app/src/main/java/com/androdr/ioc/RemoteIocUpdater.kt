package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.IocEntryDao
import com.androdr.ioc.feeds.RemoteJsonFeed
import com.androdr.ioc.feeds.StalkerwareIndicatorsFeed
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Orchestrates all configured IOC feeds: runs them in parallel, upserts results
 * into Room, prunes stale entries, then refreshes the [IocResolver] in-memory cache
 * so the new data takes effect immediately without an app restart.
 */
@Singleton
class RemoteIocUpdater @Inject constructor(
    private val iocEntryDao: IocEntryDao,
    private val iocResolver: IocResolver
) {
    private val feeds: List<IocFeed> = listOf(
        RemoteJsonFeed(
            sourceId = RemoteJsonFeed.COMMUNITY_SOURCE_ID,
            url = RemoteJsonFeed.COMMUNITY_URL
        ),
        StalkerwareIndicatorsFeed()
    )

    /**
     * Fetches all feeds concurrently, upserts into Room, prunes stale entries,
     * and refreshes [IocResolver]. Returns the total number of entries stored
     * across all feeds (0 if all feeds failed).
     */
    suspend fun update(): Int = withContext(Dispatchers.IO) {
        var totalStored = 0
        coroutineScope {
            val deferreds = feeds.map { feed ->
                async {
                    val entries = feed.fetch()
                    if (entries.isNotEmpty()) {
                        iocEntryDao.upsertAll(entries)
                        // Remove entries from this feed that weren't seen in this run
                        val runStart = entries.minOf { it.fetchedAt } - 1
                        iocEntryDao.deleteStaleEntries(feed.sourceId, runStart)
                        Log.i(TAG, "Feed '${feed.sourceId}': ${entries.size} entries upserted")
                    } else {
                        Log.w(TAG, "Feed '${feed.sourceId}': no entries returned")
                    }
                    entries.size
                }
            }
            totalStored = deferreds.sumOf { it.await() }
        }

        iocResolver.refreshCache()
        Log.i(TAG, "Update complete — total DB entries: ${iocEntryDao.count()}, fetched: $totalStored")
        totalStored
    }

    companion object {
        private const val TAG = "RemoteIocUpdater"
    }
}
