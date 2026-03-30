package com.androdr.ioc

import android.content.Context
import android.util.Log
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.repo.CveRepository
import com.androdr.data.repo.ScanRepository
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

@HiltWorker
@Suppress("LongParameterList") // All parameters are Hilt-injected dependencies
class IocUpdateWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val remoteIocUpdater: RemoteIocUpdater,
    private val domainIocUpdater: DomainIocUpdater,
    private val knownAppUpdater: KnownAppUpdater,
    private val certHashIocUpdater: CertHashIocUpdater,
    private val publicRepoIocFeed: PublicRepoIocFeed,
    private val knownAppResolver: KnownAppResolver,
    private val oemPrefixResolver: OemPrefixResolver,
    private val sigmaRuleFeed: SigmaRuleFeed,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val cveRepository: CveRepository,
    private val scanRepository: ScanRepository,
    private val forensicTimelineEventDao: ForensicTimelineEventDao
) : CoroutineWorker(context, params) {

    @Suppress("TooGenericExceptionCaught")
    override suspend fun doWork(): Result {
        return try {
            val fetched = runAllUpdaters(remoteIocUpdater, domainIocUpdater, knownAppUpdater, certHashIocUpdater)
            // Fetch IOC data from public rules repo
            refreshPublicRepoIoc()
            // Refresh OEM prefix / trusted installer lists
            refreshOemPrefixes()
            // Refresh SIGMA rules independently — never blocks IOC update success
            refreshSigmaRules()
            refreshCveDatabase()
            // Prune old data to prevent unbounded growth
            val thirtyDaysAgo = System.currentTimeMillis() - (30L * 24 * 60 * 60 * 1000)
            scanRepository.pruneOldDnsEvents(thirtyDaysAgo)
            forensicTimelineEventDao.deleteOlderThan(thirtyDaysAgo)
            Log.i(TAG, "Worker finished — $fetched IOC entries, ${sigmaRuleEngine.ruleCount()} SIGMA rules")
            Result.success()
        } catch (e: Exception) {
            // Only IOC updater failures trigger retry — SIGMA failures are caught in refreshSigmaRules()
            Log.e(TAG, "IOC update failed: ${e.message}")
            Result.retry()
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

    @Suppress("TooGenericExceptionCaught")
    private suspend fun refreshPublicRepoIoc() {
        try {
            val count = publicRepoIocFeed.update()
            if (count > 0) {
                Log.i(TAG, "Public repo IOC feed: $count entries loaded")
                // Popular apps are upserted into KnownAppEntry table by PublicRepoIocFeed,
                // so refresh the KnownAppResolver cache to pick up the new entries.
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

    companion object {
        private const val TAG = "IocUpdateWorker"
        const val WORK_NAME = "ioc_periodic_update"
    }
}

/** Runs all four updaters in parallel; returns combined entry count. Extracted for testability. */
internal suspend fun runAllUpdaters(
    remoteIoc: RemoteIocUpdater,
    domainIoc: DomainIocUpdater,
    knownApp: KnownAppUpdater,
    certHashIoc: CertHashIocUpdater
): Int = coroutineScope {
    val a = async { remoteIoc.update() }
    val b = async { domainIoc.update() }
    val c = async { knownApp.update() }
    val d = async { certHashIoc.update() }
    a.await() + b.await() + c.await() + d.await()
}
