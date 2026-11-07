package com.androdr.privacy

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.util.Log
import com.androdr.scanner.UsageAccess
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Reads foreground intervals for the privacy scan's background-lookup counts. Unlike the security scan's usage
 * collection, it keeps every package (system apps included), applies no event cap and never collapses events per
 * minute: a dropped or collapsed pause would turn background lookups into foreground ones.
 */
@Singleton
class UsageIntervalReader @Inject constructor(
    @ApplicationContext private val context: Context,
    private val usageAccess: UsageAccess,
) {
    /**
     * All ACTIVITY_RESUMED / ACTIVITY_PAUSED (and ACTIVITY_STOPPED) events in [since, until], every package.
     * null when usage access is not granted or the service is unavailable or refuses the query.
     */
    @Suppress("TooGenericExceptionCaught") // any failure means "no usage data", never an empty, clean-looking one
    fun read(since: Long, until: Long): UsageIntervals? {
        if (!usageAccess.granted()) return null
        val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager ?: return null
        return try {
            val events = collect(usm, since, until)
            // The history covers from its oldest event; with none at all, it covers nothing before [until].
            val coverageFrom = maxOf(since, events.minOfOrNull { it.time } ?: until)
            UsageIntervals(coverageFrom, ForegroundIntervals.build(events, until))
        } catch (e: Exception) {
            Log.w(TAG, "Usage events unavailable: ${e.javaClass.simpleName}")
            null
        }
    }

    private fun collect(usm: UsageStatsManager, since: Long, until: Long): List<ActivityTransition> {
        val events: UsageEvents? = usm.queryEvents(since, until)
        val out = ArrayList<ActivityTransition>()
        val event = UsageEvents.Event()
        while (events != null && events.hasNextEvent()) {
            events.getNextEvent(event)
            val kind = kindOf(event.eventType)
            // A device reset carries the system's package name; it applies to every package.
            val pkg: String? = event.packageName ?: if (kind == ActivityTransition.Kind.DEVICE_RESET) "" else null
            if (pkg != null && kind != null && event.timeStamp in since..until) {
                // The class name tells activities apart: split screen resumes two of one app at once.
                out.add(ActivityTransition(pkg, event.className, event.timeStamp, kind))
            }
        }
        return out
    }

    internal companion object {
        private const val TAG = "UsageIntervalReader"

        // Raw event types, so the constants need no API-level guard: releases that lack them never report them.
        /** `UsageEvents.Event.ACTIVITY_STOPPED` (API 29). */
        const val ACTIVITY_STOPPED = 23

        /** `UsageEvents.Event.DEVICE_SHUTDOWN` (API 28). */
        const val DEVICE_SHUTDOWN = 26

        /** `UsageEvents.Event.DEVICE_STARTUP` (API 28). */
        const val DEVICE_STARTUP = 27

        /** The transition a raw usage event type means, or null for one the privacy scan ignores. */
        fun kindOf(eventType: Int): ActivityTransition.Kind? = when (eventType) {
            UsageEvents.Event.ACTIVITY_RESUMED -> ActivityTransition.Kind.RESUMED
            UsageEvents.Event.ACTIVITY_PAUSED -> ActivityTransition.Kind.PAUSED
            ACTIVITY_STOPPED -> ActivityTransition.Kind.STOPPED
            DEVICE_SHUTDOWN, DEVICE_STARTUP -> ActivityTransition.Kind.DEVICE_RESET
            else -> null
        }
    }
}
