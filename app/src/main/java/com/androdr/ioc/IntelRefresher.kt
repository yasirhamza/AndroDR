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
    private val cveRepository: CveRepository
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
        val indicators = async { indicatorUpdater.update() }
        val knownApps = async { knownAppUpdater.update() }
        indicators.await() + knownApps.await()
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun refreshPublicRepoIoc() {
        try {
            val count = publicRepoIocFeed.update()
            if (count > 0) {
                Log.i(TAG, "Public repo IOC feed: $count entries loaded")
                knownAppResolver.refreshCache()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Public repo IOC feed failed (non-fatal): ${e.message}")
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun refreshOemPrefixes() {
        try {
            oemPrefixResolver.refresh()
        } catch (e: Exception) {
            Log.w(TAG, "OEM prefix refresh failed (non-fatal): ${e.message}")
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun refreshSigmaRules() {
        try {
            val remoteRules = sigmaRuleFeed.fetch()
            if (remoteRules.isNotEmpty()) {
                sigmaRuleEngine.setRemoteRules(remoteRules)
                Log.i(TAG, "SIGMA rules refreshed: ${remoteRules.size} remote rules loaded")
            }
        } catch (e: Exception) {
            Log.w(TAG, "SIGMA rule refresh failed: ${e.message}")
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun refreshCveDatabase() {
        try {
            cveRepository.refresh()
            Log.i(TAG, "CVE database refreshed: ${cveRepository.getActivelyExploitedCount()} Android CVEs")
        } catch (e: Exception) {
            Log.w(TAG, "CVE database refresh failed (non-fatal): ${e.message}")
        }
    }

    companion object {
        private const val TAG = "IntelRefresher"
    }
}
