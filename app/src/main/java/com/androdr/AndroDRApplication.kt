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
import com.androdr.data.repo.CveRepository
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.IocUpdateWorker
import com.androdr.ioc.KnownAppResolver
import com.androdr.sigma.SigmaRuleEngine
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit
import javax.inject.Inject

@HiltAndroidApp
class AndroDRApplication : Application(), Configuration.Provider {

    @Suppress("LateinitUsage") // Hilt @Inject requires lateinit on Application subclasses
    @Inject lateinit var workerFactory: HiltWorkerFactory
    @Suppress("LateinitUsage")
    @Inject lateinit var indicatorResolver: IndicatorResolver
    @Suppress("LateinitUsage")
    @Inject lateinit var knownAppResolver: KnownAppResolver
    @Suppress("LateinitUsage")
    @Inject lateinit var sigmaRuleEngine: SigmaRuleEngine
    @Suppress("LateinitUsage")
    @Inject lateinit var cveRepository: CveRepository

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .build()

    override fun onCreate() {
        super.onCreate()
        CoroutineScope(Dispatchers.IO).launch {
            indicatorResolver.refreshCache()
            knownAppResolver.refreshCache()
            sigmaRuleEngine.loadBundledRules()
            cveRepository.loadBundledIfEmpty()
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
