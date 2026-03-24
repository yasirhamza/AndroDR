package com.androdr

import android.app.Application
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.BackoffPolicy
import androidx.work.Configuration
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.androdr.ioc.IocResolver
import com.androdr.ioc.IocUpdateWorker
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit
import javax.inject.Inject

@HiltAndroidApp
class AndroDRApplication : Application(), Configuration.Provider {

    @Inject lateinit var workerFactory: HiltWorkerFactory
    @Inject lateinit var iocResolver: IocResolver

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .build()

    override fun onCreate() {
        super.onCreate()
        // Populate the IocResolver in-memory cache from Room on startup so that
        // any previously fetched remote IOCs are available before the next update run.
        CoroutineScope(Dispatchers.IO).launch {
            iocResolver.refreshCache()
        }
        scheduleIocUpdates()
    }

    private fun scheduleIocUpdates() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
        val request = PeriodicWorkRequestBuilder<IocUpdateWorker>(12, TimeUnit.HOURS)
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            IocUpdateWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }
}
