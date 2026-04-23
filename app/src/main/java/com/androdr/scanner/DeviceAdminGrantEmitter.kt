package com.androdr.scanner

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Emits one ForensicTimelineEvent per newly observed device-admin package on
 * each scan. Mirrors [InstallEventEmitter]: the forensic_timeline table
 * itself is the dedup store — any package already present with
 * category = "device_admin_grant" is skipped.
 *
 * Timestamps are "now" (the observation time), not the real grant time —
 * Android does not expose grant timestamps to third-party apps. Rows carry
 * timestampPrecision = "approximate" to make this explicit.
 */
@Singleton
class DeviceAdminGrantEmitter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val timelineDao: ForensicTimelineEventDao,
) {

    /**
     * Reads the current active-admin set from [DevicePolicyManager] and
     * returns timeline rows for packages not already present in the
     * forensic_timeline table with category = "device_admin_grant".
     */
    suspend fun emitNew(scanId: Long): List<ForensicTimelineEvent> {
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
            ?: return emptyList()
        // activeAdmins returns ComponentNames; multiple receivers under one
        // package (or work-profile vs primary-owner admins on the profile
        // where AndroDR runs) collapse to a single row per package via the
        // .distinct() call inside buildEvents.
        val packages = dpm.activeAdmins?.map { it.packageName } ?: return emptyList()
        if (packages.isEmpty()) return emptyList()
        return buildEvents(scanId, packages, System.currentTimeMillis(), ::resolveAppLabel)
    }

    /**
     * Internal test seam: pure logic over an explicit active-admin list,
     * a fixed `now`, and a label resolver. Keeps the unit tests free of
     * Android system-service mocking.
     */
    internal suspend fun buildEvents(
        scanId: Long,
        activeAdminPackages: List<String>,
        now: Long,
        labelFor: (String) -> String,
    ): List<ForensicTimelineEvent> {
        val unique = activeAdminPackages.distinct()
        if (unique.isEmpty()) return emptyList()
        val alreadyEmitted = timelineDao
            .getAdminGrantedPackagesAlreadyEmitted()
            .toHashSet()
        return unique
            .filter { it !in alreadyEmitted }
            .map { pkg ->
                val label = labelFor(pkg)
                ForensicTimelineEvent(
                    scanResultId = scanId,
                    startTimestamp = now,
                    timestampPrecision = "approximate",
                    kind = "event",
                    category = "device_admin_grant",
                    source = "device_admin_emitter",
                    description = "App granted device admin: $label ($pkg)",
                    packageName = pkg,
                    appName = label,
                    telemetrySource = TelemetrySource.LIVE_SCAN,
                )
            }
    }

    // Mirrors PackageLifecycleReceiver.resolveAppLabel.
    @Suppress("SwallowedException", "DEPRECATION")
    private fun resolveAppLabel(pkg: String): String = try {
        val pm = context.packageManager
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
        } else {
            pm.getApplicationInfo(pkg, 0)
        }
        pm.getApplicationLabel(info).toString()
    } catch (e: PackageManager.NameNotFoundException) {
        pkg
    }
}
