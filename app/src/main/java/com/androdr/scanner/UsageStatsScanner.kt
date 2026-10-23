package com.androdr.scanner

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.UsageEvent
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.OemPrefixResolver
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Queries UsageStatsManager for app foreground/background events in the last 24 hours and emits
 * them as [UsageEvent] records (the emitter-only `usage_stats` service: stored, shown on the
 * timeline, targeted by no rule). Until Task C3 the live scan also maps them to today's
 * `usage_stats` Timeline rows.
 *
 * Requires PACKAGE_USAGE_STATS permission granted via Settings > Apps > Special access > Usage access.
 * If permission is not granted, returns empty list gracefully.
 */
@Singleton
class UsageStatsScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val oemPrefixResolver: OemPrefixResolver
) {

    private val localDevice = DeviceIdentity.local()

    /**
     * Collects app usage events from the last [hoursBack] hours.
     * Filters out OEM/system apps to reduce noise.
     */
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    suspend fun collectEvents(
        hoursBack: Int = 24
    ): List<UsageEvent> = withContext(Dispatchers.IO) {
        require(hoursBack in 1..168) { "hoursBack must be between 1 hour and 1 week" }

        val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            ?: return@withContext emptyList()

        val endTime = System.currentTimeMillis()
        val startTime = endTime - (hoursBack * 3600_000L)

        val events = try {
            usm.queryEvents(startTime, endTime)
        } catch (e: SecurityException) {
            // PACKAGE_USAGE_STATS not granted. Previously this was logged at
            // DEBUG with a comment calling the absence "expected" — which
            // meant the forensic-timeline feature was silently disabled with
            // no signal to anyone that the user needed to grant Usage Access
            // in Settings. Promoting to WARN so the degraded state is at
            // least visible in logcat, and the Dashboard banner (see
            // UsageStatsPermission + DashboardScreen) prompts the user
            // to grant the permission via the system settings page.
            Log.w(TAG, "UsageStats permission not granted — forensic timeline " +
                "will be empty until the user enables Usage Access in Settings")
            return@withContext emptyList()
        } catch (e: Exception) {
            Log.w(TAG, "Usage stats query failed: ${e.message}")
            return@withContext emptyList()
        }

        val result = mutableListOf<UsageEvent>()
        val event = UsageEvents.Event()
        val pm = context.packageManager
        val labelCache = mutableMapOf<String, String>()

        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            processUsageEvent(event, pm, labelCache, endTime, result)
        }

        // Deduplicate rapid transitions of same app+category within same minute
        val deduped = result.distinctBy {
            "${it.packageName}|${it.eventType}|${it.timestamp / 60000}"
        }

        Log.d(TAG, "Collected ${deduped.size} usage events (from ${result.size} raw)")
        deduped
    }

    /**
     * Processes a single UsageEvents.Event and appends a [UsageEvent] to [result]
     * if the event represents a relevant foreground/background transition for a non-OEM app.
     */
    @Suppress("TooGenericExceptionCaught")
    private fun processUsageEvent(
        event: UsageEvents.Event,
        pm: PackageManager,
        labelCache: MutableMap<String, String>,
        capturedAt: Long,
        result: MutableList<UsageEvent>
    ) {
        val category = when (event.eventType) {
            UsageEvents.Event.ACTIVITY_RESUMED -> "app_foreground"
            UsageEvents.Event.ACTIVITY_PAUSED -> "app_background"
            else -> return
        }

        val packageName = event.packageName ?: return

        // Skip OEM/system apps — only track user-installed app activity
        if (oemPrefixResolver.isOemPrefix(packageName, localDevice)) return

        // Resolve app label (cached to avoid repeated PM lookups)
        val appLabel = labelCache.getOrPut(packageName) {
            try {
                pm.getApplicationLabel(
                    pm.getApplicationInfo(packageName, 0)
                ).toString()
            } catch (_: PackageManager.NameNotFoundException) {
                packageName
            } catch (_: Exception) {
                packageName
            }
        }

        result.add(
            UsageEvent(
                timestamp = event.timeStamp,
                packageName = packageName,
                appName = appLabel,
                eventType = category,
                source = TelemetrySource.LIVE_SCAN,
                capturedAt = capturedAt,
            )
        )
    }

    companion object {
        private const val TAG = "UsageStatsScanner"
    }
}
