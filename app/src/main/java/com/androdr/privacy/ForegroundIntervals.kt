package com.androdr.privacy

/** What the system's usage history says about when each app was in the foreground. */
data class UsageIntervals(
    /** The earliest time the history covers: lookups before it cannot be classed foreground or background. */
    val coverageFrom: Long,
    /** Foreground intervals per package, sorted and disjoint; a package absent here was never in the foreground. */
    val byPackage: Map<String, List<LongRange>>,
)

/** One activity of [packageName] coming to the foreground (resumed) or leaving it (paused or stopped). */
data class ActivityTransition(val packageName: String, val className: String?, val time: Long, val foreground: Boolean)

object ForegroundIntervals {
    /**
     * Each package's foreground intervals: the package is in the foreground while at least one of its activities is
     * resumed (split screen and multi-window resume several at once). Every package is kept, system apps included.
     * A resume of an already-resumed activity, or a pause of one already paused, changes nothing. The first event of
     * an activity being a pause means it was already resumed when the history begins, so the package was in the
     * foreground from [Long.MIN_VALUE] to that pause. An interval still open at the end runs to [until].
     */
    fun build(events: List<ActivityTransition>, until: Long): Map<String, List<LongRange>> {
        val out = HashMap<String, List<LongRange>>()
        for ((pkg, pkgEvents) in events.groupBy { it.packageName }) {
            out[pkg] = merge(pair(pkgEvents.sortedBy { it.time }, until))
        }
        return out
    }

    private fun pair(sorted: List<ActivityTransition>, until: Long): List<LongRange> {
        val ranges = ArrayList<LongRange>()
        val resumed = HashSet<String>()
        val seen = HashSet<String>()
        var open: Long? = null
        for (e in sorted) {
            val cls = e.className.orEmpty()
            val firstSight = seen.add(cls)
            if (e.foreground) {
                if (resumed.add(cls) && open == null) open = e.time
            } else if (resumed.remove(cls)) {
                if (resumed.isEmpty() && open != null) {
                    ranges.add(open..e.time)
                    open = null
                }
            } else if (firstSight) {
                ranges.add(Long.MIN_VALUE..e.time)
            }
        }
        open?.let { ranges.add(it..maxOf(it, until)) }
        return ranges
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
