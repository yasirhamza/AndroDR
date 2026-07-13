package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Per-feed refresh health, one row per logical threat-intel feed.
 *
 * Exists because feed failures were architecturally invisible: every layer
 * converts a failed fetch into an empty result, so a channel outage (e.g. the
 * 2026-07-03 GitHub cert-pin failure) ran for days with WorkManager reporting
 * success and the Settings "Last updated" line staying fresh — because it read
 * a global MAX(fetchedAt) that one still-healthy feed kept current. Recording
 * success/failure per feed lets the UI (and, later, a stale-intel finding)
 * distinguish "all feeds fresh" from "one feed fresh, seven dead".
 */
@Entity(tableName = "feed_health")
data class FeedHealth(
    /** Stable logical feed id, e.g. "sigma_rules", "public_repo_ioc". */
    @PrimaryKey val feedId: String,
    /** Wall-clock ms of the most recent refresh attempt (success or failure). */
    val lastAttemptAt: Long,
    /** Wall-clock ms of the most recent SUCCESSFUL refresh, 0 if never. */
    val lastSuccessAt: Long,
    /** Short reason for the last failure, null after a success. */
    val lastError: String?,
    /** Consecutive failed attempts since the last success. */
    val consecutiveFailures: Int,
)
