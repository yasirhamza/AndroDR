package com.androdr.cellular

/**
 * Holds the previous radio observation and a rolling window of TAC-change
 * timestamps.
 *
 * Computes OBJECTIVE measurements only — "the value changed", "it changed N
 * times in T ms". It never decides what is suspicious: that three changes
 * without movement constitutes churn is a judgment, and judgments belong in
 * the rules so they stay tunable without recompiling.
 *
 * A null TAC is treated as a real, distinct value rather than "no data", so a
 * transition into or out of the platform's unavailable sentinel still counts
 * as a change. Suppressing those would hide exactly the instability the churn
 * heuristic exists to notice.
 */
class RadioStateStore(private val windowMillis: Long = DEFAULT_WINDOW_MILLIS) {

    data class Derived(
        val previousTac: Int?,
        val previousRat: String?,
        val tacChanged: Boolean,
        val ratChanged: Boolean,
        val tacChangesLast5m: Int,
    )

    private var lastTac: Int? = null
    private var lastRat: String? = null
    private var seenFirst = false
    private val tacChangeTimes = ArrayDeque<Long>()

    @Synchronized
    fun record(tac: Int?, rat: String, atMillis: Long): Derived {
        val prevTac = lastTac
        val prevRat = lastRat
        val tacChanged = seenFirst && tac != prevTac
        val ratChanged = seenFirst && rat != prevRat

        if (tacChanged) tacChangeTimes.addLast(atMillis)
        while (tacChangeTimes.isNotEmpty() && atMillis - tacChangeTimes.first() > windowMillis) {
            tacChangeTimes.removeFirst()
        }

        lastTac = tac
        lastRat = rat
        seenFirst = true

        return Derived(prevTac, prevRat, tacChanged, ratChanged, tacChangeTimes.size)
    }

    companion object {
        /** The "last 5 minutes" behind tac_changes_last_5m and location_moved_m_last_5m. */
        const val DEFAULT_WINDOW_MILLIS = 300_000L
    }
}
