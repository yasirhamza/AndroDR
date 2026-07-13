package com.androdr.ioc

import com.androdr.data.db.FeedHealthDao
import com.androdr.data.model.FeedHealth
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Records the outcome of each logical threat-intel feed refresh into the
 * [FeedHealth] table. Wraps a suspending feed call: on a non-empty/successful
 * result it stamps lastSuccessAt and clears the failure streak; on an empty
 * result or a thrown exception it stamps lastAttemptAt, keeps the prior
 * lastSuccessAt, and increments consecutiveFailures.
 *
 * "Empty is failure" is deliberate: every feed here is never legitimately empty
 * (a 0-entry result means the fetch or parse failed upstream and was swallowed
 * into an empty return). That swallowing is exactly why the 2026-07-03 outage
 * was invisible — see #236.
 */
@Singleton
class FeedHealthRecorder @Inject constructor(
    private val feedHealthDao: FeedHealthDao,
) {

    /**
     * Run [block] and record health for [feedId]. [succeeded] maps the block's
     * result to success/failure (default: any non-null result is success — use
     * the count overload for feeds that report an entry count). Never throws:
     * a feed failure is recorded, not propagated, matching the existing
     * fault-tolerant refresh contract.
     */
    @Suppress("TooGenericExceptionCaught") // feed contract: record any failure, never propagate
    suspend fun <T> record(
        feedId: String,
        succeeded: (T) -> Boolean,
        block: suspend () -> T,
    ): T? {
        val now = nowMs()
        val prior = feedHealthDao.get(feedId)
        return try {
            val result = block()
            if (succeeded(result)) {
                feedHealthDao.upsert(
                    FeedHealth(
                        feedId = feedId,
                        lastAttemptAt = now,
                        lastSuccessAt = now,
                        lastError = null,
                        consecutiveFailures = 0,
                    ),
                )
            } else {
                recordFailure(feedId, now, prior, "empty result")
            }
            result
        } catch (e: Exception) {
            recordFailure(feedId, now, prior, e.message ?: e.javaClass.simpleName)
            null
        }
    }

    /** Convenience for count-returning feeds: success iff count > 0. */
    suspend fun recordCount(feedId: String, block: suspend () -> Int): Int =
        record(feedId, succeeded = { it > 0 }, block = block) ?: 0

    private suspend fun recordFailure(feedId: String, now: Long, prior: FeedHealth?, error: String) {
        feedHealthDao.upsert(
            FeedHealth(
                feedId = feedId,
                lastAttemptAt = now,
                lastSuccessAt = prior?.lastSuccessAt ?: 0L,
                lastError = error,
                consecutiveFailures = (prior?.consecutiveFailures ?: 0) + 1,
            ),
        )
    }

    private fun nowMs(): Long = System.currentTimeMillis()

    companion object {
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
         * (the 2026-07-03 outage channel). Surfaced first in health UIs.
         */
        val CRITICAL_FEEDS = setOf(FEED_SIGMA_RULES, FEED_PUBLIC_REPO_IOC)
    }
}
