package com.androdr.ioc

import android.content.Context
import android.util.Log
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

@HiltWorker
class IocUpdateWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val remoteIocUpdater: RemoteIocUpdater,
    private val domainIocUpdater: DomainIocUpdater,
    private val knownAppUpdater: KnownAppUpdater
) : CoroutineWorker(context, params) {

    @Suppress("TooGenericExceptionCaught")
    override suspend fun doWork(): Result {
        return try {
            val fetched = runAllUpdaters(remoteIocUpdater, domainIocUpdater, knownAppUpdater)
            Log.i(TAG, "Worker finished — $fetched entries fetched total")
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

/** Runs all three updaters in parallel; returns combined entry count. Extracted for testability. */
internal suspend fun runAllUpdaters(
    remoteIoc: RemoteIocUpdater,
    domainIoc: DomainIocUpdater,
    knownApp: KnownAppUpdater
): Int = coroutineScope {
    val a = async { remoteIoc.update() }
    val b = async { domainIoc.update() }
    val c = async { knownApp.update() }
    a.await() + b.await() + c.await()
}
