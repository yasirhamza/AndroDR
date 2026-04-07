package com.androdr.scanner

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.ForensicTimelineEvent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Emits one ForensicTimelineEvent per newly installed package on each scan.
 *
 * Forensic value of an install event is "this happened" — re-emitting on every
 * scan only adds noise. We dedupe against prior scans by querying which package
 * names already have a package_install row.
 */
@Singleton
class InstallEventEmitter @Inject constructor(
    private val timelineDao: ForensicTimelineEventDao
) {
    suspend fun emitNew(scanId: Long, telemetry: List<AppTelemetry>): List<ForensicTimelineEvent> {
        val alreadyEmitted = timelineDao.getInstalledPackagesAlreadyEmitted().toHashSet()
        return telemetry
            .filter { it.firstInstallTime > 0L }
            .filter { it.packageName !in alreadyEmitted }
            .map { t ->
                ForensicTimelineEvent(
                    scanResultId = scanId,
                    startTimestamp = t.firstInstallTime,
                    kind = "event",
                    category = "package_install",
                    source = "app_scanner",
                    description = "Package installed: ${t.appName}",
                    severity = "info",
                    packageName = t.packageName,
                    appName = t.appName,
                    isFromRuntime = true
                )
            }
    }
}
