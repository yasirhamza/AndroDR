package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.FeedHealthDao
import com.androdr.data.model.FeedHealth
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Records the outcome of each logical threat-intel feed refresh into the
 * [FeedHealth] table. Wraps a suspending feed call: on a successful result it
 * stamps lastSuccessAt and clears the failure streak; on an empty result or a
 * thrown exception it stamps lastAttemptAt, keeps the prior lastSuccessAt, and
 * increments consecutiveFailures.
 *
 * "Empty is failure" holds for the count/list feeds routed here, whose updaters
 * return 0 / an empty list precisely when the fetch or parse failed and was
 * swallowed upstream — the swallowing that made the 2026-07-03 outage invisible
 * (#236). It does NOT hold for a feed that can be legitimately empty (e.g. a
 * stub feed); such a feed must not be routed through recordCount.
 *
 * Recording NEVER propagates: neither a failing feed nor a failing DB write
 * aborts the caller's refresh sequence.
 *
 * Concurrency: callers must use one writer per feedId at a time (the current
 * callers satisfy this — runBulkUpdaters runs distinct feedIds concurrently and
 * refreshMutex single-flights the rest), so the read-then-write of the failure
 * streak is race-free without a transaction.
 */
@Singleton
class FeedHealthRecorder @Inject constructor(
    private val feedHealthDao: FeedHealthDao,
) {

    /**
     * Run [block] and record health for [feedId]. [succeeded] maps the block's
     * result to success/failure. Returns the block's result, or null if [block]
     * itself threw. Never throws: a feed failure OR a DB-write failure is
     * recorded/logged, not propagated — matching IntelRefresher's fault-tolerant
     * "each step independent" contract.
     */
    @Suppress("TooGenericExceptionCaught") // feed contract: record any failure, never propagate
    suspend fun <T> record(
        feedId: String,
        succeeded: (T) -> Boolean,
        block: suspend () -> T,
    ): T? {
        val now = nowMs()
        // block() runs OUTSIDE any DB call so a fetch exception and a DB-write
        // exception are handled distinctly — a successful fetch is never
        // misrecorded as a failure just because the health upsert failed.
        val result: T = try {
            block()
        } catch (e: Exception) {
            recordFailureSafe(feedId, now, e.message ?: e.javaClass.simpleName)
            return null
        }
        if (succeeded(result)) {
            recordSuccessSafe(feedId, now)
        } else {
            recordFailureSafe(feedId, now, "empty result")
        }
        return result
    }

    /** Convenience for count-returning feeds: success iff count > 0. */
    suspend fun recordCount(feedId: String, block: suspend () -> Int): Int =
        record(feedId, succeeded = { it > 0 }, block = block) ?: 0

    @Suppress("TooGenericExceptionCaught")
    private suspend fun recordSuccessSafe(feedId: String, now: Long) {
        try {
            feedHealthDao.upsert(
                FeedHealth(feedId, lastAttemptAt = now, lastSuccessAt = now, lastError = null, consecutiveFailures = 0),
            )
        } catch (e: Exception) {
            Log.w(TAG, "feed_health upsert failed for $feedId (success): ${e.message}")
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun recordFailureSafe(feedId: String, now: Long, error: String) {
        Log.w(TAG, "Feed $feedId refresh failed: $error")
        try {
            val prior = feedHealthDao.get(feedId)
            feedHealthDao.upsert(
                FeedHealth(
                    feedId = feedId,
                    lastAttemptAt = now,
                    lastSuccessAt = prior?.lastSuccessAt ?: 0L,
                    lastError = error,
                    consecutiveFailures = (prior?.consecutiveFailures ?: 0) + 1,
                ),
            )
        } catch (e: Exception) {
            Log.w(TAG, "feed_health upsert failed for $feedId (failure): ${e.message}")
        }
    }

    private fun nowMs(): Long = System.currentTimeMillis()

    companion object {
        private const val TAG = "FeedHealthRecorder"

        // Stable feed ids — keep in sync with the refresh calls in IntelRefresher.
        const val FEED_INDICATORS = "indicators"
        const val FEED_KNOWN_APPS = "known_apps"
        const val FEED_PUBLIC_REPO_IOC = "public_repo_ioc"
        const val FEED_OEM_PREFIXES = "oem_prefixes"
        const val FEED_SIGMA_RULES = "sigma_rules"
        const val FEED_CVE = "cve"

        /**
         * The detection-content feeds whose staleness matters most: the SIGMA
         * rules and the curated public-repo IOCs both ride raw.githubusercontent.com
         * (the 2026-07-03 outage channel). Surfaced first in health UIs, and held
         * to the tighter [STALE_CRITICAL_MS] window.
         */
        val CRITICAL_FEEDS = setOf(FEED_SIGMA_RULES, FEED_PUBLIC_REPO_IOC)

        /** Human labels for the feed ids, for health UIs. */
        val FEED_LABELS = mapOf(
            FEED_SIGMA_RULES to "SIGMA rules",
            FEED_PUBLIC_REPO_IOC to "Curated IOCs",
            FEED_INDICATORS to "Bulk indicators",
            FEED_KNOWN_APPS to "Known apps",
            FEED_OEM_PREFIXES to "OEM prefixes",
            FEED_CVE to "CVE database",
        )

        // Staleness thresholds live here (shared by the Settings badge and any
        // future stale-intel finding, so they cannot disagree). The refresh
        // cadence is 12h; a non-critical feed is stale after 6 missed cycles,
        // a critical detection-content feed after ~3.
        const val STALE_MS = 3L * 24 * 60 * 60 * 1000        // 3 days
        const val STALE_CRITICAL_MS = 36L * 60 * 60 * 1000   // 36 hours
        /** A hard-failure streak this long flags stale even if lastSuccessAt is recent. */
        const val STALE_FAILURE_STREAK = 3

        /** Whether a feed with this last-success age + failure streak is stale. */
        fun isStale(feedId: String, lastSuccessAt: Long, consecutiveFailures: Int, now: Long): Boolean {
            val threshold = if (feedId in CRITICAL_FEEDS) STALE_CRITICAL_MS else STALE_MS
            return lastSuccessAt < now - threshold || consecutiveFailures >= STALE_FAILURE_STREAK
        }
    }
}
