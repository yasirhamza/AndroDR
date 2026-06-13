package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.CertHashIocEntry
import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.IocEntry
import com.androdr.data.model.Indicator
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
            total = (pkgJobs + domJobs + certJobs).sumOf { it.await() }
        }
        resolver.refreshCache()
        Log.i(TAG, "Indicator update complete — fetched: $total, DB: ${dao.count()}")
        total
    }

    private suspend fun runFeed(sourceId: String, fetch: suspend () -> List<Indicator>): Int {
        val entries = fetch()
        if (entries.isNotEmpty()) {
            // Upsert in bounded chunks rather than one giant transaction. A single
            // `upsertAll` of a large feed (e.g. hagezi_tif ~540k rows) holds the
            // sole write connection for the entire run, starving reader threads on
            // the connection pool for tens of seconds (observed ~28s) and stalling
            // the UI. Each chunk is its own transaction, so the write lock is
            // released between batches and readers can interleave.
            //
            // Tradeoff: the feed write is no longer atomic with the
            // deleteStaleEntries below — a crash mid-feed leaves new + old rows
            // coexisting. That is benign for an IOC cache (PK is (type,value)
            // with REPLACE, and the next successful sync self-heals), and is the
            // intended price for not holding one long write lock.
            entries.chunked(UPSERT_CHUNK_SIZE).forEach { chunk -> dao.upsertAll(chunk) }
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

        /**
         * Rows per upsert transaction. Bounds how long the single write lock is
         * held per batch so reader threads on the connection pool are not starved
         * during a bulk feed sync, while keeping per-batch overhead low.
         *
         * This is a transaction-duration knob, not a binding-count limit: Room's
         * `@Insert(List)` compiles one statement and executes it per row, so
         * SQLite's ~999-variable limit does not apply. Value is empirically in
         * the range that keeps lock-release frequent without excessive batches.
         */
        internal const val UPSERT_CHUNK_SIZE = 2_000
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
