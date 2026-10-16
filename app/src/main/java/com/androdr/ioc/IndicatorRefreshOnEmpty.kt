package com.androdr.ioc

import androidx.work.Constraints
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequest
import androidx.work.OneTimeWorkRequestBuilder
import com.androdr.data.db.IndicatorDao

/**
 * Schema 19 drops the indicators table (see MIGRATION_18_19), so the first open after the
 * upgrade finds it empty. Enqueue a one-time refresh then; bundled lists cover cold start.
 */
object IndicatorRefreshOnEmpty {
    const val WORK_NAME = "ioc_refresh_on_empty"

    suspend fun maybeEnqueue(dao: IndicatorDao, enqueue: () -> Unit) {
        if (dao.count() == 0) enqueue()
    }

    /**
     * Deliberately NOT expedited: expedited work below API 31 runs as a foreground service and
     * [IocUpdateWorker] has no getForegroundInfo().
     */
    fun buildEmptyTableRefreshRequest(): OneTimeWorkRequest =
        OneTimeWorkRequestBuilder<IocUpdateWorker>()
            .setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
            )
            .build()
}
