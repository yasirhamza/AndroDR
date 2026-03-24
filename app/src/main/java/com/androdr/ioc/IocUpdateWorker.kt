package com.androdr.ioc

import android.content.Context
import android.util.Log
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

/**
 * Periodic WorkManager job that triggers a full IOC feed update.
 *
 * Scheduled every 12 hours (when network is available). On failure it retries
 * with exponential back-off up to the WorkManager default ceiling.
 */
@HiltWorker
class IocUpdateWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val remoteIocUpdater: RemoteIocUpdater
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        return try {
            val fetched = remoteIocUpdater.update()
            Log.i(TAG, "Worker finished — $fetched entries fetched")
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Worker failed: ${e.message}")
            Result.retry()
        }
    }

    companion object {
        private const val TAG = "IocUpdateWorker"
        const val WORK_NAME = "ioc_periodic_update"
    }
}
