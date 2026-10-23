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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Queries UsageStatsManager for app foreground/background events in a window and emits them as
 * [UsageEvent] records (the emitter-only `usage_stats` service: stored, shown on the timeline,
 * targeted by no rule). The live scan reads from its usage watermark (spec §5.2, [Watermarks]).
 * Until Task C3 the live scan also maps them to today's `usage_stats` Timeline rows.
 *
 * Requires PACKAGE_USAGE_STATS, granted via Settings > Apps > Special access > Usage access. It is
 * checked explicitly ([UsageAccess]); without it the collection is [UsageCollection.NoAccess] (the
 * Dashboard banner prompts the user), never an empty list that reads like "no activity".
 */
@Singleton
class UsageStatsScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val oemPrefixResolver: OemPrefixResolver,
    private val usageAccess: UsageAccess,
) {

    private val localDevice = DeviceIdentity.local()

    /**
     * Collects app usage events with `sinceMs <= timestamp <= untilMs`, filtering out OEM/system
     * apps to reduce noise. A query failure is [UsageCollection.Failed], so the watermark stays put.
     */
    @Suppress("TooGenericExceptionCaught")
    suspend fun collectEvents(sinceMs: Long, untilMs: Long): UsageCollection = withContext(Dispatchers.IO) {
        require(sinceMs <= untilMs) { "usage window starts after it ends: $sinceMs > $untilMs" }
        if (!usageAccess.granted()) {
            Log.w(TAG, "Usage Access not granted: usage events not collected")
            return@withContext UsageCollection.NoAccess
        }
        val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            ?: return@withContext UsageCollection.Failed(IllegalStateException("UsageStatsManager unavailable"))
        try {
            UsageCollection.Ok(read(usm, sinceMs, untilMs))
        } catch (c: CancellationException) {
            throw c
        } catch (e: SecurityException) {
            // Revoked between the check and the query.
            Log.w(TAG, "Usage Access revoked during the query: ${e.message}")
            UsageCollection.NoAccess
        } catch (e: Exception) {
            Log.w(TAG, "Usage stats query failed: ${e.message}")
            UsageCollection.Failed(e)
        }
    }

    private fun read(usm: UsageStatsManager, sinceMs: Long, untilMs: Long): List<UsageEvent> {
        val events = usm.queryEvents(sinceMs, untilMs)
        val result = mutableListOf<UsageEvent>()
        val event = UsageEvents.Event()
        val pm = context.packageManager
        val labelCache = mutableMapOf<String, String>()

        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            if (event.timeStamp in sinceMs..untilMs) processUsageEvent(event, pm, labelCache, untilMs, result)
        }

        // Deduplicate rapid transitions of same app+category within same minute
        val deduped = result.distinctBy {
            "${it.packageName}|${it.eventType}|${it.timestamp / 60000}"
        }

        Log.d(TAG, "Collected ${deduped.size} usage events (from ${result.size} raw)")
        return deduped
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
