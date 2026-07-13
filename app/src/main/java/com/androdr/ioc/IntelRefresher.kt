package com.androdr.ioc

import android.util.Log
import com.androdr.data.repo.CveRepository
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Runs the full threat-intel refresh sequence shared by all three entry points:
 * the periodic [IocUpdateWorker] (every 12h), the manual pre-scan refresh in
 * DashboardViewModel, and the manual Settings "Update" button. Routing every
 * caller here is what keeps feed_health recording uniform — a call straight to
 * the updaters records no health row (the bug behind #244).
 *
 * Each step is independently fault-tolerant: a single feed failure is logged,
 * not propagated, so a partial outage still updates the feeds that succeeded.
 * This class deliberately does NOT prune old data — pruning stays in the
 * periodic worker so it isn't run on every user-initiated scan.
 */
@Singleton
@Suppress("LongParameterList") // All parameters are Hilt-injected dependencies
class IntelRefresher @Inject constructor(
    private val indicatorUpdater: IndicatorUpdater,
    private val knownAppUpdater: KnownAppUpdater,
    private val publicRepoIocFeed: PublicRepoIocFeed,
    private val knownAppResolver: KnownAppResolver,
    private val oemPrefixResolver: OemPrefixResolver,
    private val sigmaRuleFeed: SigmaRuleFeed,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val cveRepository: CveRepository,
    private val feedHealthRecorder: FeedHealthRecorder
) {

    private val refreshMutex = Mutex()

    @Volatile
    private var lastRefreshAt = 0L

    /**
     * Per-feed outcome of one [refreshAll], so a caller that renders results
     * (the manual Settings "Update" dialog) can report each feed without
     * duplicating the refresh logic or bypassing the health recording. Counts
     * are the same this-run signals recorded to feed_health: >0 means the feed
     * reached its source this run; 0 means it failed or returned empty (the
     * "empty is failure" contract, see [FeedHealthRecorder]). Deliberately
     * carries no error text — matching the #236 decision to keep
     * attacker-influenceable exception strings out of the UI.
     */
    data class RefreshReport(
        val skipped: Boolean = false,
        val indicators: Int = 0,
        val knownApps: Int = 0,
        val oemPrefixes: Int = 0,
        val sigmaRemoteRules: Int = 0,
        val cveReachable: Int = 0,
    ) {
        /** IOC entry count from the bulk feeds — the legacy `refreshAll` return. */
        val bulkFetchedCount: Int get() = indicators + knownApps
    }

    /**
     * Refreshes every threat-intel feed (bulk IOC feeds, the curated public
     * rule-repo IOCs, OEM prefixes, SIGMA rules, and CVEs), recording per-feed
     * health for each. Returns a [RefreshReport] of the per-feed this-run
     * signals. Safe to call from any coroutine context.
     *
     * Every entry point — the periodic [IocUpdateWorker], the manual pre-scan
     * refresh, and the manual Settings "Update" button — MUST route through
     * here so all three record feed_health identically (a direct call to the
     * updaters writes no health row — the bug behind #244).
     *
     * Single-flighted via [refreshMutex]: at most one refresh runs at a time.
     * A caller that arrives while another refresh is in flight **waits** for it
     * (so e.g. a manual pre-scan refresh blocks the scan until fresh intel has
     * landed) rather than racing ahead with stale data.
     *
     * @param skipIfRefreshedWithinMs once the lock is acquired, if a refresh
     * completed less than this long ago, skip the work and return a
     * [RefreshReport] with `skipped = true` — the data is already fresh, so
     * there's no point re-downloading the same ~6–8 MB. This is what makes the
     * "wait for the in-flight refresh, then don't redo it" path cheap. Pass 0
     * to always refresh (the manual paths do, so a user tap always re-records
     * health even right after a periodic run).
     */
    suspend fun refreshAll(skipIfRefreshedWithinMs: Long = 0L): RefreshReport = refreshMutex.withLock {
        val now = System.currentTimeMillis()
        if (skipIfRefreshedWithinMs > 0L && lastRefreshAt != 0L &&
            now - lastRefreshAt < skipIfRefreshedWithinMs
        ) {
            Log.i(TAG, "Intel refreshed ${(now - lastRefreshAt) / 1000}s ago — reusing, skipping refresh")
            return@withLock RefreshReport(skipped = true)
        }
        // Each feed runs in a fixed order with real network + DB side effects, so
        // they're sequenced as explicit statements (not inline RefreshReport args,
        // whose evaluation order would silently follow field order).
        val (indicators, knownApps) = runBulkUpdaters()
        refreshPublicRepoIoc()
        val oemPrefixes = refreshOemPrefixes()
        val sigmaRemoteRules = refreshSigmaRules()
        val cveReachable = refreshCveDatabase()
        lastRefreshAt = System.currentTimeMillis()
        RefreshReport(
            skipped = false,
            indicators = indicators,
            knownApps = knownApps,
            oemPrefixes = oemPrefixes,
            sigmaRemoteRules = sigmaRemoteRules,
            cveReachable = cveReachable,
        )
    }

    private suspend fun runBulkUpdaters(): Pair<Int, Int> = coroutineScope {
        val indicators = async {
            feedHealthRecorder.recordCount(FeedHealthRecorder.FEED_INDICATORS) { indicatorUpdater.update() }
        }
        val knownApps = async {
            feedHealthRecorder.recordCount(FeedHealthRecorder.FEED_KNOWN_APPS) { knownAppUpdater.update() }
        }
        indicators.await() to knownApps.await()
    }

    private suspend fun refreshPublicRepoIoc() {
        val count = feedHealthRecorder.recordCount(FeedHealthRecorder.FEED_PUBLIC_REPO_IOC) {
            publicRepoIocFeed.update()
        }
        if (count > 0) {
            Log.i(TAG, "Public repo IOC feed: $count entries loaded")
            knownAppResolver.refreshCache()
        }
    }

    private suspend fun refreshOemPrefixes(): Int {
        // refresh() returns prefixes accepted this run (0 on any failure), a real
        // success signal — the feed's URL is on the raw.githubusercontent.com
        // channel, so a false-green here would hide the 2026-07-03 outage class.
        return feedHealthRecorder.recordCount(FeedHealthRecorder.FEED_OEM_PREFIXES) {
            oemPrefixResolver.refresh()
        }
    }

    private suspend fun refreshSigmaRules(): Int {
        val remoteRules = feedHealthRecorder.record(
            FeedHealthRecorder.FEED_SIGMA_RULES,
            succeeded = { it.isNotEmpty() },
        ) { sigmaRuleFeed.fetch() }
        if (remoteRules != null && remoteRules.isNotEmpty()) {
            sigmaRuleEngine.setRemoteRules(remoteRules)
            Log.i(TAG, "SIGMA rules refreshed: ${remoteRules.size} remote rules loaded")
        }
        return remoteRules?.size ?: 0
    }

    private suspend fun refreshCveDatabase(): Int {
        // refresh() now returns a this-run reachability signal (>0 = CISA fetched
        // or 304 unchanged; 0 = CISA errored) rather than a standing DB total, so
        // a swallowed fetch error can't false-green the feed.
        val reachable = feedHealthRecorder.recordCount(FeedHealthRecorder.FEED_CVE) {
            cveRepository.refresh()
        }
        if (reachable > 0) {
            Log.i(TAG, "CVE database refreshed: ${cveRepository.getActivelyExploitedCount()} Android CVEs")
        }
        return reachable
    }

    companion object {
        private const val TAG = "IntelRefresher"
    }
}
