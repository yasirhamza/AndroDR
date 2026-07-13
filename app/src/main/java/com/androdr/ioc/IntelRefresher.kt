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
 * Runs the full threat-intel refresh sequence shared by the periodic
 * [IocUpdateWorker] (every 12h) and the manual pre-scan refresh in
 * DashboardViewModel.
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
     * Refreshes every threat-intel feed (bulk IOC feeds, the curated public
     * rule-repo IOCs, OEM prefixes, SIGMA rules, and CVEs). Returns the IOC
     * entry count reported by the bulk feed updaters. Safe to call from any
     * coroutine context.
     *
     * Single-flighted via [refreshMutex]: at most one refresh runs at a time.
     * A caller that arrives while another refresh is in flight **waits** for it
     * (so e.g. a manual pre-scan refresh blocks the scan until fresh intel has
     * landed) rather than racing ahead with stale data.
     *
     * @param skipIfRefreshedWithinMs once the lock is acquired, if a refresh
     * completed less than this long ago, skip the work and return 0 — the data
     * is already fresh, so there's no point re-downloading the same ~6–8 MB.
     * This is what makes the "wait for the in-flight refresh, then don't redo
     * it" path cheap. Pass 0 to always refresh.
     */
    suspend fun refreshAll(skipIfRefreshedWithinMs: Long = 0L): Int = refreshMutex.withLock {
        val now = System.currentTimeMillis()
        if (skipIfRefreshedWithinMs > 0L && lastRefreshAt != 0L &&
            now - lastRefreshAt < skipIfRefreshedWithinMs
        ) {
            Log.i(TAG, "Intel refreshed ${(now - lastRefreshAt) / 1000}s ago — reusing, skipping refresh")
            return@withLock 0
        }
        val fetched = runBulkUpdaters()
        refreshPublicRepoIoc()
        refreshOemPrefixes()
        refreshSigmaRules()
        refreshCveDatabase()
        lastRefreshAt = System.currentTimeMillis()
        fetched
    }

    private suspend fun runBulkUpdaters(): Int = coroutineScope {
        val indicators = async {
            feedHealthRecorder.recordCount(FeedHealthRecorder.FEED_INDICATORS) { indicatorUpdater.update() }
        }
        val knownApps = async {
            feedHealthRecorder.recordCount(FeedHealthRecorder.FEED_KNOWN_APPS) { knownAppUpdater.update() }
        }
        indicators.await() + knownApps.await()
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

    private suspend fun refreshOemPrefixes() {
        // Unit-returning refresh: the only failure signal is a thrown exception,
        // which the recorder converts to a null result + failure row.
        feedHealthRecorder.record(
            FeedHealthRecorder.FEED_OEM_PREFIXES,
            succeeded = { true },
        ) { oemPrefixResolver.refresh() }
    }

    private suspend fun refreshSigmaRules() {
        val remoteRules = feedHealthRecorder.record(
            FeedHealthRecorder.FEED_SIGMA_RULES,
            succeeded = { it.isNotEmpty() },
        ) { sigmaRuleFeed.fetch() }
        if (remoteRules != null && remoteRules.isNotEmpty()) {
            sigmaRuleEngine.setRemoteRules(remoteRules)
            Log.i(TAG, "SIGMA rules refreshed: ${remoteRules.size} remote rules loaded")
        }
    }

    private suspend fun refreshCveDatabase() {
        val count = feedHealthRecorder.recordCount(FeedHealthRecorder.FEED_CVE) {
            cveRepository.refresh()
            cveRepository.getActivelyExploitedCount()
        }
        if (count > 0) {
            Log.i(TAG, "CVE database refreshed: $count Android CVEs")
        }
    }

    companion object {
        private const val TAG = "IntelRefresher"
    }
}
