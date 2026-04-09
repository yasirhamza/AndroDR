package com.androdr.scanner

import android.app.ActivityManager
import android.content.Context
import android.util.Log
import com.androdr.data.model.ProcessTelemetry
import com.androdr.data.model.TelemetrySource
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Enumerates running processes via [ActivityManager.getRunningAppProcesses] and returns
 * one [ProcessTelemetry] record per process. The telemetry feeds into the SIGMA rule engine
 * for process-based detection (e.g. known-bad process names, unexpected foreground services).
 */
@Singleton
class ProcessScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {

    /**
     * Collects telemetry for every running app process visible to this application.
     *
     * Note: On Android 7+ (API 24), [ActivityManager.getRunningAppProcesses] is restricted
     * to the caller's own processes and a few system processes. On older devices or with
     * shell/root access, the full process list is available.
     */
    suspend fun collectTelemetry(): List<ProcessTelemetry> = withContext(Dispatchers.IO) {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            ?: return@withContext emptyList()
        val processes = am.runningAppProcesses ?: return@withContext emptyList()
        processes.map { proc ->
            ProcessTelemetry(
                processName = proc.processName,
                processUid = proc.uid,
                packageName = proc.pkgList?.firstOrNull(),
                isForeground = proc.importance ==
                    ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND,
                source = TelemetrySource.LIVE_SCAN,
            )
        }.also {
            Log.d(TAG, "Collected ${it.size} running process records")
        }
    }

    companion object {
        private const val TAG = "ProcessScanner"
    }
}
