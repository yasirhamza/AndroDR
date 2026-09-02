package com.androdr.cellular

import com.androdr.data.model.CellularSnapshot

/**
 * Recognises the same physical observation delivered twice.
 *
 * `arm()` reads the current cell list once to prime the view, and on some
 * devices registering the callback ALSO delivers that same list immediately.
 * Both went through `handle()`, so every session start produced two identical
 * observations and — whenever a rule matched — two identical findings in the
 * same second. A repeated finding is not corroboration; it is the same
 * evidence counted twice, and it inflated every count downstream.
 *
 * A duplicate is: identical raw radio facts ([CellularSnapshot.observationKey])
 * within [windowMillis] of the last ACCEPTED observation. The window is
 * measured from the accepted one, not from the previous duplicate, so a run
 * of identical deliveries cannot suppress itself indefinitely. Outside the
 * window the same facts are a new observation: a stationary radio reporting
 * the same cell a minute later IS evidence — that nothing changed.
 *
 * Pure and clock-free: the caller stamps the snapshot, the filter compares.
 */
class DuplicateDeliveryFilter(private val windowMillis: Long = DEFAULT_WINDOW_MILLIS) {

    private var lastKey: Map<String, Any?>? = null
    private var lastAcceptedAt = 0L

    /**
     * True if [snapshot] repeats the last accepted observation within the
     * window. A non-duplicate becomes the new reference.
     */
    @Synchronized
    fun isDuplicate(snapshot: CellularSnapshot): Boolean {
        val key = snapshot.observationKey()
        val duplicate = key == lastKey && snapshot.capturedAt - lastAcceptedAt <= windowMillis
        if (!duplicate) {
            lastKey = key
            lastAcceptedAt = snapshot.capturedAt
        }
        return duplicate
    }

    companion object {
        /**
         * Prime and the registration callback land within the same second;
         * two seconds is generous for that and far shorter than any real
         * radio re-report interval.
         */
        const val DEFAULT_WINDOW_MILLIS = 2_000L
    }
}
