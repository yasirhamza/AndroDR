package com.androdr.privacy

/** What the system's usage history says about when each app was in the foreground. */
data class UsageIntervals(
    /** The earliest time the history covers: lookups before it cannot be classed foreground or background. */
    val coverageFrom: Long,
    /** Foreground intervals per package, sorted and disjoint; a package absent here was never in the foreground. */
    val byPackage: Map<String, List<LongRange>>,
)

/**
 * One usage event: an activity of [packageName] resumed, paused or stopped, or a device-level [Kind.DEVICE_RESET]
 * (shutdown or startup), which applies to every package and ignores [packageName] and [className].
 */
data class ActivityTransition(val packageName: String, val className: String?, val time: Long, val kind: Kind) {
    enum class Kind { RESUMED, PAUSED, STOPPED, DEVICE_RESET }
}

/**
 * Foreground intervals from usage events. Every inference here errs toward background, never toward foreground:
 * foreground time hides background lookups, so an over-long interval would make an app look cleaner than it is.
 */
object ForegroundIntervals {
    /**
     * Each package's foreground intervals: the package is in the foreground while at least one of its activity
     * classes is resumed (split screen and multi-window resume several at once). Every package is kept, system apps
     * included.
     * - A resume of an already-resumed class changes nothing. Two open instances of the same activity class count as
     *   one: public `UsageEvents` carry no instance id (accepted).
     * - A pause or stop removes its class from the resumed set; a pause or stop of a class not in the set has no
     *   effect, with one exception: a PAUSE that is the package's first event of any kind, with no device reset
     *   before it, means the app was already in the foreground when the history begins (`Long.MIN_VALUE..t`).
     *   A stop never creates an interval.
     * - A [ActivityTransition.Kind.DEVICE_RESET] closes every open interval at its time and clears every resumed
     *   set, so a pause lost to a crash or reboot cannot hold an app in the foreground.
     * - An interval still open at the end runs to [until].
     */
    fun build(events: List<ActivityTransition>, until: Long): Map<String, List<LongRange>> {
        val resets = events.filter { it.kind == ActivityTransition.Kind.DEVICE_RESET }
        val out = HashMap<String, List<LongRange>>()
        val byPackage = events.filter { it.kind != ActivityTransition.Kind.DEVICE_RESET }.groupBy { it.packageName }
        for ((pkg, pkgEvents) in byPackage) {
            // Stable sort: at equal times a reset applies before the package's own events.
            out[pkg] = merge(PackageState().replay((resets + pkgEvents).sortedBy { it.time }, until))
        }
        return out
    }

    private class PackageState {
        val ranges = ArrayList<LongRange>()
        val resumed = HashSet<String>()
        var open: Long? = null
        var sawPackageEvent = false
        var sawReset = false

        fun replay(sorted: List<ActivityTransition>, until: Long): List<LongRange> {
            for (e in sorted) {
                when (e.kind) {
                    ActivityTransition.Kind.DEVICE_RESET -> reset(e.time)
                    ActivityTransition.Kind.RESUMED -> resume(e)
                    ActivityTransition.Kind.PAUSED, ActivityTransition.Kind.STOPPED -> leave(e)
                }
            }
            open?.let { ranges.add(it..maxOf(it, until)) }
            return ranges
        }

        private fun reset(time: Long) {
            sawReset = true
            close(time)
        }

        private fun resume(e: ActivityTransition) {
            sawPackageEvent = true
            if (resumed.add(e.className.orEmpty()) && open == null) open = e.time
        }

        private fun leave(e: ActivityTransition) {
            val first = !sawPackageEvent
            sawPackageEvent = true
            when {
                resumed.remove(e.className.orEmpty()) -> if (resumed.isEmpty()) close(e.time)
                first && !sawReset && e.kind == ActivityTransition.Kind.PAUSED -> ranges.add(Long.MIN_VALUE..e.time)
            }
        }

        private fun close(time: Long) {
            open?.let { ranges.add(it..maxOf(it, time)) }
            open = null
            resumed.clear()
        }
    }

    /** Sorted, overlap-free copy of [ranges], so a binary search over them is exact. */
    fun merge(ranges: List<LongRange>): List<LongRange> {
        val out = ArrayList<LongRange>()
        for (r in ranges.filter { !it.isEmpty() }.sortedBy { it.first }) {
            val last = out.lastOrNull()
            if (last != null && r.first <= last.last) out[out.size - 1] = last.first..maxOf(last.last, r.last)
            else out.add(r)
        }
        return out
    }
}
