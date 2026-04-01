package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.CertHashIocEntry
import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.IocEntry
import com.androdr.data.model.Indicator
import com.androdr.ioc.feeds.MalwareBazaarApkHashFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Unified IOC feed orchestrator. Runs all package, domain, and cert hash
 * feeds in parallel, converts results to [Indicator] entities, and upserts
 * into the unified `indicators` table.
 */
@Singleton
class IndicatorUpdater @Inject constructor(
    private val dao: IndicatorDao,
    private val resolver: IndicatorResolver,
    private val domainFeeds: @JvmSuppressWildcards List<DomainIocFeed>,
    private val certHashFeeds: @JvmSuppressWildcards List<CertHashIocFeed>,
    private val packageFeeds: @JvmSuppressWildcards List<IocFeed>
) {
    private val apkHashFeed = MalwareBazaarApkHashFeed()
    private val updateMutex = Mutex()

    suspend fun update(): Int {
        if (!updateMutex.tryLock()) {
            Log.d(TAG, "Update already in progress — skipping")
            return 0
        }
        return try { doUpdate() } finally { updateMutex.unlock() }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun doUpdate(): Int = withContext(Dispatchers.IO) {
        var total = 0
        coroutineScope {
            // Package feeds
            val pkgJobs = packageFeeds.map { feed ->
                async { runFeed(feed.sourceId) { feed.fetch().map { it.toIndicator() } } }
            }
            // Domain feeds
            val domJobs = domainFeeds.map { feed ->
                async { runFeed(feed.sourceId) { feed.fetch().map { it.toIndicator() } } }
            }
            // Cert hash feeds
            val certJobs = certHashFeeds.map { feed ->
                async { runFeed(feed.sourceId) { feed.fetch().map { it.toIndicator() } } }
            }
            // APK hash feed (MalwareBazaar recent Android samples)
            val apkHashJob = async {
                runFeed(apkHashFeed.sourceId) { apkHashFeed.fetch() }
            }
            total = (pkgJobs + domJobs + certJobs + listOf(apkHashJob)).sumOf { it.await() }
        }
        resolver.refreshCache()
        Log.i(TAG, "Indicator update complete — fetched: $total, DB: ${dao.count()}")
        total
    }

    private suspend fun runFeed(sourceId: String, fetch: suspend () -> List<Indicator>): Int {
        val entries = fetch()
        if (entries.isNotEmpty()) {
            dao.upsertAll(entries)
            val runStart = entries.minOf { it.fetchedAt } - 1
            dao.deleteStaleEntries(sourceId, runStart)
            Log.i(TAG, "Feed '$sourceId': ${entries.size} indicators upserted")
        } else {
            Log.w(TAG, "Feed '$sourceId': no entries returned")
        }
        return entries.size
    }

    companion object {
        private const val TAG = "IndicatorUpdater"
    }
}

// Conversion functions from per-type entities to unified Indicator
internal fun IocEntry.toIndicator() = Indicator(
    type = IndicatorResolver.TYPE_PACKAGE, value = packageName,
    name = name, campaign = category, severity = severity,
    description = description, source = source, fetchedAt = fetchedAt
)

internal fun DomainIocEntry.toIndicator() = Indicator(
    type = IndicatorResolver.TYPE_DOMAIN, value = domain.lowercase(),
    name = "", campaign = campaignName, severity = severity,
    description = "", source = source, fetchedAt = fetchedAt
)

internal fun CertHashIocEntry.toIndicator() = Indicator(
    type = IndicatorResolver.TYPE_CERT_HASH, value = certHash,
    name = familyName, campaign = category, severity = severity,
    description = description, source = source, fetchedAt = fetchedAt
)
