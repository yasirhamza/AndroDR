package com.androdr.cellular

import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * The recent location fixes, kept only long enough to answer "has the
 * device moved in the last few minutes?" — which is what separates a
 * tracking area that changes because the phone is on a motorway from one
 * that changes while the phone sits on a desk (androdr-104's "while
 * stationary", hard-coded null until now).
 *
 * Pure: fed fixes by the platform reader, asked for distance and age by the
 * emitter. Coordinates never leave this object — they are not emitted, not
 * persisted and not logged; only the distance and the fix age are.
 *
 * The passive provider hands over whatever fix some other app most
 * recently obtained, so a fix can be minutes or hours old. Age is
 * therefore reported alongside distance, and distance is null rather than
 * zero when fewer than two fixes fall inside the window: "did not move"
 * and "do not know" must stay distinguishable for a rule that gates on
 * stationarity.
 */
class LocationTrail(private val retentionMillis: Long = DEFAULT_RETENTION_MILLIS) {

    private data class Fix(val latitude: Double, val longitude: Double, val timeMillis: Long)

    /** Oldest first. */
    private val fixes = ArrayDeque<Fix>()

    /** Records a fix; a repeat of the newest fix's timestamp is the same fix and is ignored. */
    @Synchronized
    fun record(latitude: Double, longitude: Double, timeMillis: Long) {
        if (fixes.lastOrNull()?.timeMillis == timeMillis) return
        fixes.addLast(Fix(latitude, longitude, timeMillis))
        while (fixes.size > 1 && fixes.first().timeMillis < timeMillis - retentionMillis) fixes.removeFirst()
    }

    /**
     * Greatest distance, in metres, between the newest fix and any fix taken
     * within [windowMillis] before [now]. Null when fewer than two fixes fall
     * inside the window — movement is then unknown, not zero.
     */
    @Synchronized
    fun movedMetersLast(windowMillis: Long, now: Long): Int? {
        val recent = fixes.filter { it.timeMillis >= now - windowMillis && it.timeMillis <= now }
        if (recent.size < 2) return null
        val newest = recent.last()
        return recent.maxOf { haversineMeters(newest, it) }.roundToInt()
    }

    /** Seconds since the newest fix; null when there has never been one. */
    @Synchronized
    fun fixAgeSeconds(now: Long): Int? =
        fixes.lastOrNull()?.let { ((now - it.timeMillis) / MILLIS_PER_SECOND).coerceAtLeast(0).toInt() }

    private fun haversineMeters(a: Fix, b: Fix): Double {
        val dLat = Math.toRadians(b.latitude - a.latitude)
        val dLon = Math.toRadians(b.longitude - a.longitude)
        val h = sin(dLat / 2) * sin(dLat / 2) +
            cos(Math.toRadians(a.latitude)) * cos(Math.toRadians(b.latitude)) * sin(dLon / 2) * sin(dLon / 2)
        return 2 * EARTH_RADIUS_METERS * asin(sqrt(h))
    }

    companion object {
        /** Twice the rule window, so a fix just outside five minutes is still there for the next read. */
        const val DEFAULT_RETENTION_MILLIS = 10 * 60_000L
        private const val MILLIS_PER_SECOND = 1_000L
        private const val EARTH_RADIUS_METERS = 6_371_000.0
    }
}
