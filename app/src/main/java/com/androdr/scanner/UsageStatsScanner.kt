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
 * [UsageEvent] records (the emitter-only `usage_stats` service: stored, read by the Timeline from
 * the store, targeted by no rule). The live scan reads from its usage watermark (spec §5.2,
 * [Watermarks]). One collection holds at most [maxEvents] events, oldest first: after a long
 * watermark gap the watermark stops at the last event read and the next scan continues from there,
 * so nothing is dropped and no scan holds everything Android keeps at once.
 *
 * Requires PACKAGE_USAGE_STATS, granted via Settings > Apps > Special access > Usage access. It is
 * checked explicitly ([UsageAccess]); without it the collection is [UsageCollection.NoAccess] (the
 * Dashboard banner prompts the user), never an empty list that reads like "no activity".
 */
@Singleton
class UsageStatsScanner internal constructor(
    private val context: Context,
    private val oemPrefixResolver: OemPrefixResolver,
    private val usageAccess: UsageAccess,
    private val maxEvents: Int,
) {
    @Inject constructor(
        @ApplicationContext context: Context,
        oemPrefixResolver: OemPrefixResolver,
        usageAccess: UsageAccess,
    ) : this(context, oemPrefixResolver, usageAccess, MAX_EVENTS_PER_SCAN)

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

    /**
     * The window's events, oldest first, with rapid transitions of the same app and category
     * within the same minute collapsed to the first; stops at [maxEvents] kept events.
     */
    private fun read(usm: UsageStatsManager, sinceMs: Long, untilMs: Long): List<UsageEvent> {
        val events = usm.queryEvents(sinceMs, untilMs)
        val result = ArrayList<UsageEvent>()
        val seen = HashSet<String>()
        val event = UsageEvents.Event()
        val pm = context.packageManager
        val labelCache = mutableMapOf<String, String>()
        var raw = 0

        while (result.size < maxEvents && events.hasNextEvent()) {
            events.getNextEvent(event)
            val usage = event.takeIf { it.timeStamp in sinceMs..untilMs }
                ?.let { toUsageEvent(it, pm, labelCache, untilMs) }
            if (usage != null) {
                raw++
                if (seen.add("${usage.packageName}|${usage.eventType}|${usage.timestamp / MINUTE_MS}")) result += usage
            }
        }
        if (result.size >= maxEvents) {
            Log.i(TAG, "Usage collection reached $maxEvents events; the next scan continues from the last one")
        }
        Log.d(TAG, "Collected ${result.size} usage events (from $raw raw)")
        return result
    }

    /**
     * The [UsageEvent] for one UsageEvents.Event, or null unless it is a foreground/background
     * transition of a non-OEM app.
     */
    @Suppress("TooGenericExceptionCaught")
    private fun toUsageEvent(
        event: UsageEvents.Event,
        pm: PackageManager,
        labelCache: MutableMap<String, String>,
        capturedAt: Long,
    ): UsageEvent? {
        val category = when (event.eventType) {
            UsageEvents.Event.ACTIVITY_RESUMED -> "app_foreground"
            UsageEvents.Event.ACTIVITY_PAUSED -> "app_background"
            else -> return null
        }

        // Skip OEM/system apps — only track user-installed app activity
        val packageName = event.packageName?.takeUnless { oemPrefixResolver.isOemPrefix(it, localDevice) }
            ?: return null

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

        return UsageEvent(
            timestamp = event.timeStamp,
            packageName = packageName,
            appName = appLabel,
            eventType = category,
            source = TelemetrySource.LIVE_SCAN,
            capturedAt = capturedAt,
        )
    }

    companion object {
        private const val TAG = "UsageStatsScanner"
        private const val MINUTE_MS = 60_000L

        /**
         * Usage events one collection holds (C1 m4). A heavy day is a few thousand transitions
         * after the per-minute collapse, so 20,000 covers a first 24 h collection; a longer gap is
         * read over the following scans from the watermark. (It can only stall if 20,000 collapsed
         * events fall inside one 5-minute re-read window: over 2,000 apps active in one minute.)
         */
        const val MAX_EVENTS_PER_SCAN = 20_000
    }
}
