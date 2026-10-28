package com.androdr.ioc

import android.content.Context
import android.util.Log
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import kotlinx.coroutines.CancellationException
import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.repo.TimelineRowDeleter
import com.androdr.data.repo.ScanRepository
import com.androdr.data.store.TelemetryRetention
import com.androdr.sigma.SigmaRuleEngine

@HiltWorker
class IocUpdateWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val intelRefresher: IntelRefresher,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val scanRepository: ScanRepository,
    private val database: AppDatabase,
    private val timelineRows: TimelineRowDeleter,
    private val retention: TelemetryRetention,
) : CoroutineWorker(context, params) {

    @Suppress("TooGenericExceptionCaught")
    override suspend fun doWork(): Result {
        return try {
            val report = intelRefresher.refreshAll(skipIfRefreshedWithinMs = RECENT_REFRESH_SKIP_MS)
            val thirtyDaysAgo = System.currentTimeMillis() - (30L * 24 * 60 * 60 * 1000)
            scanRepository.pruneOldDnsEvents(thirtyDaysAgo)
            database.withTransaction { timelineRows.olderThan(thirtyDaysAgo) }
            runRetention()
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

    /**
     * Telemetry retention (spec §5.1), after the IOC fetch. A failed batch has already set the store's
     * dirty flag (the startup sweep's GC finishes it), so it neither fails nor retries the IOC update.
     */
    @Suppress("TooGenericExceptionCaught")
    private suspend fun runRetention() {
        try {
            val outcome = retention.run()
            Log.i(TAG, "Retention removed ${outcome.observationsRemoved} observation(s)" +
                if (outcome.completed) "" else "; skipped the rest: a scan holds the lock")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Retention failed: ${e.message}")
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
