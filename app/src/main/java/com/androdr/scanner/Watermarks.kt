package com.androdr.scanner

import com.androdr.data.db.DnsEventDao
import kotlin.math.max
import kotlin.math.min

/**
 * Per-service collection watermarks of the live event sources (spec §5.2 Watermarks), so a live
 * scan collects each event once: live DNS by `DnsEvent.id`, usage stats by event time. A watermark
 * advances on every committed scan whose collection did not fail — including when the service's
 * rules were capability-skipped — never past the scan start, and not on the disk-full fallback.
 * A null answer means "keep the previous watermark" (nothing is written).
 */
object Watermarks {
    /** Usage stats are re-read from this long before the watermark (events the OS records late). */
    const val USAGE_REREAD_MS = 5L * 60_000L

    /** Where a first collection starts, and the late-IOC re-check's trailing window. */
    const val LIVE_LOOKBACK_MS = 24L * 3_600_000L

    /**
     * The usage watermark after a committed scan: the latest event collected (the scan start when
     * none), never behind [previous] and never past [scanStart]. A [previous] ahead of [now] is
     * treated as absent (a clock that moved back must not freeze collection).
     */
    fun nextTime(
        previous: Long?, collection: UsageCollection, scanStart: Long, now: Long, saveFallback: Boolean,
    ): Long? {
        if (saveFallback || collection !is UsageCollection.Ok) return null
        val prev = previous?.takeIf { it <= now }
        val latest = collection.events.maxOfOrNull { it.timestamp } ?: scanStart
        return min(max(latest, prev ?: 0L), scanStart)
    }

    /**
     * The DNS watermark after a committed scan: the id the scan collected through ([DnsRange.untilId]),
     * or [previous] when nothing is stored at all.
     */
    fun nextDnsId(previous: Long?, collectedMaxId: Long?, failed: Boolean, saveFallback: Boolean): Long? =
        if (failed || saveFallback) null else collectedMaxId ?: previous

    /** Where a usage collection starts: [USAGE_REREAD_MS] before a usable watermark, else the last 24 h. */
    fun usageSince(previous: Long?, now: Long): Long =
        previous?.takeIf { it <= now }?.let { it - USAGE_REREAD_MS } ?: (now - LIVE_LOOKBACK_MS)
}

/**
 * The live DNS rows one scan collects: ids in `(afterId, untilId]`. Collected by id, not by time,
 * so a row the VPN's log buffer flushes late (an older timestamp, a higher id) is never missed.
 */
data class DnsRange(val afterId: Long, val untilId: Long) {
    companion object {
        /**
         * The range after [previous] up to the newest row, or — with no watermark, or one past the
         * newest row — the rows of the last 24 h before [now]. Null when no DNS row is stored.
         */
        suspend fun of(dao: DnsEventDao, previous: Long?, now: Long): DnsRange? {
            val newest = dao.maxId() ?: return null
            val after = previous?.takeIf { it <= newest }
                ?: dao.minIdSince(now - Watermarks.LIVE_LOOKBACK_MS)?.let { it - 1 }
                ?: newest
            return DnsRange(after, newest)
        }
    }
}

/** A live scan's usage collection and the watermark it started from. */
data class UsageWindow(val previous: Long?, val since: Long, val until: Long, val collection: UsageCollection)

/** A live scan's DNS range ([range] null: nothing stored) and the watermark it started from. */
data class DnsWindow(val previous: Long?, val range: DnsRange?, val failed: Boolean)
