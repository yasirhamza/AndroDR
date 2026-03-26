package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.IocEntryDao
import com.androdr.ioc.feeds.StalkerwareIndicatorsFeed
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
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
    // community_json (RemoteJsonFeed) omitted: the known_bad_packages.json file lives in a private
    // repo so its raw GitHub URL returns 404 on every run. The bundled IOC data is already loaded
    // via IocDatabase. Re-add RemoteJsonFeed here once the repo is public.
    private val feeds: List<IocFeed> = listOf(
        StalkerwareIndicatorsFeed()
    )

    /** Guards against concurrent update calls (e.g. WorkManager + user-triggered scan). */
    private val updateMutex = Mutex()

    /**
     * Fetches all feeds concurrently, upserts into Room, prunes stale entries,
     * and refreshes [IocResolver]. Returns the total number of entries stored
     * across all feeds, or 0 if all feeds failed or an update is already in progress.
     */
    suspend fun update(): Int {
        if (!updateMutex.tryLock()) {
            Log.d(TAG, "Update already in progress — skipping concurrent call")
            return 0
        }
        return try { doUpdate() } finally { updateMutex.unlock() }
    }

    private suspend fun doUpdate(): Int = withContext(Dispatchers.IO) {
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
