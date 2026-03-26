package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.CertHashIocEntryDao
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CertHashIocUpdater @Inject constructor(
    private val certHashIocEntryDao: CertHashIocEntryDao,
    private val certHashIocResolver: CertHashIocResolver,
    private val feeds: @JvmSuppressWildcards List<CertHashIocFeed>
) {
    private val updateMutex = Mutex()

    suspend fun update(): Int {
        if (!updateMutex.tryLock()) {
            Log.d(TAG, "Cert hash update already in progress — skipping concurrent call")
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
                        certHashIocEntryDao.upsertAll(entries)
                        val runStart = entries.minOf { it.fetchedAt } - 1
                        certHashIocEntryDao.deleteStaleEntries(feed.sourceId, runStart)
                        Log.i(TAG, "Cert hash feed '${feed.sourceId}': ${entries.size} entries upserted")
                    } else {
                        Log.d(TAG, "Cert hash feed '${feed.sourceId}': no entries returned")
                    }
                    entries.size
                }
            }
            totalStored = deferreds.sumOf { it.await() }
        }
        certHashIocResolver.refreshCache()
        Log.i(TAG, "Cert hash update complete — fetched: $totalStored, DB: ${certHashIocEntryDao.count()}")
        totalStored
    }

    companion object {
        private const val TAG = "CertHashIocUpdater"
    }
}
