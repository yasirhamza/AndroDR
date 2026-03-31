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
    private val indicatorUpdater: IndicatorUpdater,
    private val knownAppUpdater: KnownAppUpdater,
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
            val fetched = runAllUpdaters()
            refreshPublicRepoIoc()
            refreshOemPrefixes()
            refreshSigmaRules()
            refreshCveDatabase()
            val thirtyDaysAgo = System.currentTimeMillis() - (30L * 24 * 60 * 60 * 1000)
            scanRepository.pruneOldDnsEvents(thirtyDaysAgo)
            forensicTimelineEventDao.deleteOlderThan(thirtyDaysAgo)
            Log.i(TAG, "Worker finished — $fetched IOC entries, ${sigmaRuleEngine.ruleCount()} SIGMA rules")
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "IOC update failed: ${e.message}")
            Result.retry()
        }
    }

    private suspend fun runAllUpdaters(): Int = coroutineScope {
        val indicators = async { indicatorUpdater.update() }
        val knownApps = async { knownAppUpdater.update() }
        indicators.await() + knownApps.await()
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
