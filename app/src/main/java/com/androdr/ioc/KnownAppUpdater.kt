package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.KnownAppDbEntry
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.data.model.KnownAppEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class KnownAppUpdater @Inject constructor(
    private val dao: KnownAppEntryDao,
    private val resolver: KnownAppResolver,
    @JvmSuppressWildcards private val feeds: List<KnownAppFeed>
) {
    suspend fun update(): Int = withContext(Dispatchers.IO) {
        var totalStored = 0
        coroutineScope {
            val deferreds = feeds.map { feed ->
                async {
                    val entries = feed.fetch()
                    if (entries.isNotEmpty()) {
                        dao.upsertAll(entries.map { it.toDbEntry() })
                        val runStart = entries.minOf { it.fetchedAt } - 1
                        dao.deleteStaleEntries(feed.sourceId, runStart)
                        Log.i(TAG, "Known-app feed '${feed.sourceId}': ${entries.size} entries upserted")
                    } else {
                        Log.w(TAG, "Known-app feed '${feed.sourceId}': no entries returned")
                    }
                    entries.size
                }
            }
            totalStored = deferreds.sumOf { it.await() }
        }
        resolver.refreshCache()
        Log.i(TAG, "Known-app update complete — fetched: $totalStored, DB: ${dao.count()}")
        totalStored
    }

    companion object {
        private const val TAG = "KnownAppUpdater"
    }
}

private fun KnownAppEntry.toDbEntry() = KnownAppDbEntry(
    packageName = packageName,
    displayName = displayName,
    category    = category.name,
    sourceId    = sourceId,
    fetchedAt   = fetchedAt
)
