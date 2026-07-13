package com.androdr.ioc

import android.content.Context
import android.util.Log
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.repo.ScanRepository
import com.androdr.sigma.SigmaRuleEngine

@HiltWorker
class IocUpdateWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val intelRefresher: IntelRefresher,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val scanRepository: ScanRepository,
    private val forensicTimelineEventDao: ForensicTimelineEventDao
) : CoroutineWorker(context, params) {

    @Suppress("TooGenericExceptionCaught")
    override suspend fun doWork(): Result {
        return try {
            val report = intelRefresher.refreshAll(skipIfRefreshedWithinMs = RECENT_REFRESH_SKIP_MS)
            val thirtyDaysAgo = System.currentTimeMillis() - (30L * 24 * 60 * 60 * 1000)
            scanRepository.pruneOldDnsEvents(thirtyDaysAgo)
            forensicTimelineEventDao.deleteOlderThan(thirtyDaysAgo)
            Log.i(
                TAG,
                "Worker finished — ${report.bulkFetchedCount} IOC entries, " +
                    "${sigmaRuleEngine.ruleCount()} SIGMA rules",
            )
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "IOC update failed: ${e.message}")
            Result.retry()
        }
    }

    companion object {
        private const val TAG = "IocUpdateWorker"
        const val WORK_NAME = "ioc_periodic_update"

        /**
         * If a refresh (e.g. a manual pre-scan one) completed within this
         * window, the periodic worker reuses it instead of re-downloading.
         * The worker's real cadence is 12h, so this only ever suppresses a
         * redundant back-to-back refresh.
         */
        private const val RECENT_REFRESH_SKIP_MS = 5L * 60 * 1000 // 5 minutes
    }
}
