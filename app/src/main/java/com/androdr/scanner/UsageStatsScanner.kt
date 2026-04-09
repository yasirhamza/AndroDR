package com.androdr.scanner

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.ioc.OemPrefixResolver
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Queries UsageStatsManager for app foreground/background events in the last 24 hours.
 * Produces ForensicTimelineEvent entries directly (not telemetry maps) because these
 * are observational timeline data, not detection signals evaluated by SIGMA rules.
 *
 * Requires PACKAGE_USAGE_STATS permission granted via Settings > Apps > Special access > Usage access.
 * If permission is not granted, returns empty list gracefully.
 */
@Singleton
class UsageStatsScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val oemPrefixResolver: OemPrefixResolver
) {

    /**
     * Collects app usage events from the last [hoursBack] hours.
     * Filters out OEM/system apps to reduce noise. Returns events
     * suitable for direct insertion into the forensic timeline.
     */
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    suspend fun collectTimelineEvents(
        hoursBack: Int = 24
    ): List<ForensicTimelineEvent> = withContext(Dispatchers.IO) {
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

        val result = mutableListOf<ForensicTimelineEvent>()
        val event = UsageEvents.Event()
        val pm = context.packageManager
        val labelCache = mutableMapOf<String, String>()

        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            processUsageEvent(event, pm, labelCache, result)
        }

        // Deduplicate rapid transitions of same app+category within same minute
        val deduped = result.distinctBy {
            "${it.packageName}|${it.category}|${it.startTimestamp / 60000}"
        }

        Log.d(TAG, "Collected ${deduped.size} usage events (from ${result.size} raw)")
        deduped
    }

    /**
     * Processes a single UsageEvents.Event and appends a ForensicTimelineEvent to [result]
     * if the event represents a relevant foreground/background transition for a non-OEM app.
     */
    @Suppress("TooGenericExceptionCaught")
    private fun processUsageEvent(
        event: UsageEvents.Event,
        pm: PackageManager,
        labelCache: MutableMap<String, String>,
        result: MutableList<ForensicTimelineEvent>
    ) {
        val (category, verb) = when (event.eventType) {
            UsageEvents.Event.ACTIVITY_RESUMED -> "app_foreground" to "opened"
            UsageEvents.Event.ACTIVITY_PAUSED -> "app_background" to "closed"
            else -> return
        }

        val packageName = event.packageName ?: return

        // Skip OEM/system apps — only track user-installed app activity
        if (oemPrefixResolver.isOemPrefix(packageName) ||
            oemPrefixResolver.isPartnershipPrefix(packageName)) return

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

        result.add(ForensicTimelineEvent(
            startTimestamp = event.timeStamp,
            source = "usage_stats",
            category = category,
            description = "App $verb: $appLabel",
            packageName = packageName,
            appName = appLabel,
            telemetrySource = com.androdr.data.model.TelemetrySource.LIVE_SCAN
        ))
    }

    companion object {
        private const val TAG = "UsageStatsScanner"
    }
}
