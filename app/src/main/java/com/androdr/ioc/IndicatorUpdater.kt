package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.CertHashIocEntry
import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.IocEntry
import com.androdr.data.model.Indicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
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

    /**
     * @param refreshCache rebuild [IndicatorResolver]'s cache and bloom index after the write.
     * [IntelRefresher] passes false and rebuilds once itself after the rules-repo feed, so the
     * ~540k-domain bloom index is not built twice per refresh.
     */
    suspend fun update(refreshCache: Boolean = true): Int {
        if (!updateMutex.tryLock()) {
            Log.d(TAG, "Update already in progress — skipping")
            return 0
        }
        return try { doUpdate(refreshCache) } finally { updateMutex.unlock() }
    }

    private class FeedRows(val sourceId: String, val rows: List<Indicator>)

    @Suppress("TooGenericExceptionCaught")
    private suspend fun doUpdate(refreshCache: Boolean): Int = withContext(Dispatchers.IO) {
        var total = 0
        coroutineScope {
            // Fetch every feed in parallel...
            val jobs = packageFeeds.map { feed ->
                async { fetchFeed(feed.sourceId) { feed.fetch().map { it.toIndicator() } } }
            } + domainFeeds.map { feed ->
                async { fetchFeed(feed.sourceId) { feed.fetch().map { it.toIndicator() } } }
            } + certHashFeeds.map { feed ->
                async { fetchFeed(feed.sourceId) { feed.fetch().map { it.toIndicator() } } }
            }
            val fetched = jobs.awaitAll()
            // ...then write sequentially in ascending precedence (HaGeZi first). Order only keeps the
            // write sequence deterministic; the owned-values filter in writeFeed guarantees precedence.
            fetched.sortedBy { SourceRank.of(it.sourceId) }.forEach { total += writeFeed(it) }
        }
        if (refreshCache) resolver.refreshCache()
        Log.i(TAG, "Indicator update complete — fetched: $total, DB: ${dao.count()}")
        total
    }

    private suspend fun fetchFeed(sourceId: String, fetch: suspend () -> List<Indicator>): FeedRows =
        FeedRows(sourceId, fetch())

    private suspend fun writeFeed(feed: FeedRows): Int {
        val entries = feed.rows
        if (entries.isEmpty()) {
            Log.w(TAG, "Feed '${feed.sourceId}': no entries returned")
            return 0
        }
        // A lower-ranked feed never overwrites a value a higher-ranked source owns (spec R18).
        val (above, mvt) = SourceRank.above(feed.sourceId)
        val toWrite = entries.groupBy { it.type }.flatMap { (type, rows) ->
            val owned = dao.ownedValues(type, above, mvt).toHashSet()
            if (owned.isEmpty()) rows else rows.filter { it.value !in owned }
        }
        // Upsert in bounded chunks rather than one giant transaction. A single
        // `upsertAll` of a large feed (e.g. hagezi_tif ~540k rows) holds the
        // sole write connection for the entire run, starving reader threads on
        // the connection pool for tens of seconds (observed ~28s) and stalling
        // the UI. Each chunk is its own transaction, so the write lock is
        // released between batches and readers can interleave.
        //
        // Tradeoff: the feed write is no longer atomic with the eviction below —
        // a crash mid-feed leaves new + old rows coexisting. That is benign for an
        // IOC cache (PK is (type,value) with REPLACE, and the next successful sync
        // self-heals), and is the intended price for not holding one long write lock.
        toWrite.chunked(UPSERT_CHUNK_SIZE).forEach { chunk -> dao.upsertAll(chunk) }
        // Evict per (source, type) among the rows this feed returned: a collection whose
        // download failed contributes no rows, so it is never evicted.
        val runStart = entries.minOf { it.fetchedAt } - 1
        entries.map { it.source to it.type }.distinct().forEach { (source, type) ->
            dao.deleteStaleEntriesOfType(source, type, runStart)
        }
        Log.i(TAG, "Feed '${feed.sourceId}': ${toWrite.size}/${entries.size} indicators upserted")
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

// Conversion functions from per-type entities to unified Indicator.
// Mirror-feed rows store reference = "": attribution() derives feed:<source>#<family> at read time.
internal fun IocEntry.toIndicator() = IocSanitizer.sanitize(Indicator(
    type = IndicatorResolver.TYPE_PACKAGE, value = packageName,
    family = name, category = category, severity = severity,
    description = description, source = source, fetchedAt = fetchedAt
))

internal fun DomainIocEntry.toIndicator() = IocSanitizer.sanitize(Indicator(
    type = IndicatorResolver.TYPE_DOMAIN, value = domain.lowercase(),
    family = campaignName, category = "", severity = severity,
    source = source, fetchedAt = fetchedAt
))

internal fun CertHashIocEntry.toIndicator() = IocSanitizer.sanitize(Indicator(
    type = IndicatorResolver.TYPE_CERT_HASH, value = certHash,
    family = familyName, category = category, severity = severity,
    description = description, source = source, fetchedAt = fetchedAt
))
