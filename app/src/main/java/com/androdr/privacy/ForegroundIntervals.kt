package com.androdr.privacy

/** What the system's usage history says about when each app was in the foreground. */
data class UsageIntervals(
    /** The earliest time the history covers: lookups before it cannot be classed foreground or background. */
    val coverageFrom: Long,
    /** Foreground intervals per package, sorted and disjoint; a package absent here was never in the foreground. */
    val byPackage: Map<String, List<LongRange>>,
)

object ForegroundIntervals {
    /**
     * Pairs each package's foreground and background transitions (by time) into closed intervals. Every package is
     * kept, system apps included. A foreground event while already open, or a background event while closed, is
     * ignored, except that a package's first event being a background one means the app was already in the
     * foreground when the history begins, so that interval starts at [Long.MIN_VALUE]. An interval still open at
     * the end runs to [until].
     */
    fun build(events: List<Pair<String, Pair<Long, Boolean>>>, until: Long): Map<String, List<LongRange>> {
        val out = HashMap<String, List<LongRange>>()
        for ((pkg, pkgEvents) in events.groupBy({ it.first }, { it.second })) {
            out[pkg] = pair(pkgEvents.sortedBy { it.first }, until)
        }
        return out
    }

    private fun pair(sorted: List<Pair<Long, Boolean>>, until: Long): List<LongRange> {
        val ranges = ArrayList<LongRange>()
        var open: Long? = null
        for ((index, event) in sorted.withIndex()) {
            val (time, foreground) = event
            when {
                foreground && open == null -> open = time
                !foreground && open != null -> {
                    ranges.add(open..time)
                    open = null
                }
                !foreground && index == 0 -> ranges.add(Long.MIN_VALUE..time)
            }
        }
        open?.let { ranges.add(it..maxOf(it, until)) }
        return ranges
    }
}
