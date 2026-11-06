package com.androdr.privacy

import com.androdr.data.db.DomainLookupCount
import com.androdr.privacy.NetworkEvidenceCorrelator.Correlation
import com.androdr.privacy.NetworkEvidenceCorrelator.DnsSource
import com.androdr.privacy.NetworkEvidenceCorrelator.Key
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_DOMAINS_PER_APP
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_MATCHED_PAIRS
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_MATCHED_PER_APP
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_MEMO
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_TIMED_PAIRS
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_TIMES_PER_PAIR
import com.androdr.privacy.NetworkEvidenceCorrelator.NetworkEvidence
import com.androdr.privacy.NetworkEvidenceCorrelator.PAGE_SIZE
import com.androdr.privacy.model.TrackerSet

/** One [NetworkEvidenceCorrelator.correlate] call: its memo, quotas and partial results. Single-use. */
internal class CorrelationRun(
    private val source: DnsSource,
    private val registry: TrackerSet,
    private val usage: UsageIntervals?,
    private val expired: () -> Boolean,
) {
    /** One counted (app, raw domain); shared by every tracker that owns the domain. */
    private class Part(val app: String, val raw: String, val lookups: Int, val days: Set<Long>, val first: Long,
        val last: Long)

    private val memo = HashMap<String, List<Int>>()
    private val parts = LinkedHashMap<Key, MutableList<Part>>()
    private val partBackground = HashMap<Part, Int?>()
    private val foreground = HashMap<String, List<LongRange>>()
    private var counted = 0
    private var truncated = false
    private var stopped = false

    suspend fun run(apps: List<String>): Correlation {
        val left = apps.iterator()
        while (!stopped && counted < MAX_MATCHED_PAIRS && left.hasNext()) {
            val app = left.next()
            val matched = match(app)
            if (!stopped) count(app, matched)
        }
        // The overall cap stops the remaining apps unread: conservatively, truncated.
        if (left.hasNext()) truncated = true
        val background = if (stopped) emptyMap() else timeBackground()
        return Correlation(evidence(background), truncated || stopped)
    }

    /** Checks the deadline once; once passed, it stays passed. */
    private fun deadlinePassed(): Boolean {
        if (!stopped && expired()) stopped = true
        return stopped
    }

    /** Phase 1: the app's matched raw domains, each with the ids of the trackers that own it. */
    private suspend fun match(app: String): List<Pair<String, List<Int>>> {
        val out = ArrayList<Pair<String, List<Int>>>()
        var after = ""
        var seen = 0
        var more = true
        while (more && seen < MAX_DOMAINS_PER_APP && !deadlinePassed()) {
            val limit = minOf(PAGE_SIZE, MAX_DOMAINS_PER_APP - seen)
            val page = source.domainsAfter(app, after, limit)
            for (raw in page) {
                val ids = trackersOf(raw)
                if (ids.isNotEmpty()) out.add(raw to ids)
            }
            seen += page.size
            more = page.size == limit
            if (page.isNotEmpty()) after = page.last()
        }
        // The quota was reached with a full page: only a probe tells whether domains were left unread.
        if (more && !deadlinePassed() && source.domainsAfter(app, after, 1).isNotEmpty()) truncated = true
        return out
    }

    private fun trackersOf(raw: String): List<Int> {
        val host = NetworkEvidenceCorrelator.normalise(raw)
        memo[host]?.let { return it }
        val ids = registry.matchDomain(host).map { it.id }.distinct()
        // A full memo stops memoising, never matching.
        if (memo.size < MAX_MEMO) memo[host] = ids
        return ids
    }

    /** Phase 2: counts the app's matched raw domains within its own quota and the overall one. */
    private suspend fun count(app: String, matched: List<Pair<String, List<Int>>>) {
        var used = 0
        for ((raw, ids) in coverTrackersFirst(matched)) {
            if (used >= MAX_MATCHED_PER_APP || counted >= MAX_MATCHED_PAIRS) {
                truncated = true
                return
            }
            if (deadlinePassed()) return
            val c = source.count(app, raw)
            used++
            counted++
            val part = toPart(app, raw, c) ?: continue
            for (id in ids) parts.getOrPut(Key(app, id)) { ArrayList() }.add(part)
        }
    }

    /**
     * Domains that bring a tracker not yet seen for this app first, so many subdomains of one tracker spend the
     * app's quota only after each of its trackers has had one count.
     */
    private fun coverTrackersFirst(matched: List<Pair<String, List<Int>>>): List<Pair<String, List<Int>>> {
        val seen = HashSet<Int>()
        val (first, rest) = matched.partition { (_, ids) -> ids.count { seen.add(it) } > 0 }
        return first + rest
    }

    /** null = nothing left to count (rows pruned by age between paging and counting). */
    private fun toPart(app: String, raw: String, c: DomainLookupCount): Part? {
        val first = c.firstAt
        val last = c.lastAt
        if (c.lookups <= 0 || first == null || last == null) return null
        val days = c.dayList.orEmpty().split(',').mapNotNull { it.trim().toLongOrNull() }.toSet()
        return Part(app, raw, c.lookups, days, first, last)
    }

    /** Phase 3: background lookups for the [MAX_TIMED_PAIRS] pairs with the most lookups. */
    private suspend fun timeBackground(): Map<Key, Int?> {
        val u = usage ?: return emptyMap()
        val out = HashMap<Key, Int?>()
        val ranked = parts.entries.sortedByDescending { (_, ps) -> ps.sumOf { it.lookups.toLong() } }
        for ((key, ps) in ranked.take(MAX_TIMED_PAIRS)) {
            if (stopped) break
            if (ps.sumOf { it.lookups.toLong() } <= MAX_TIMES_PER_PAIR) out[key] = backgroundOf(ps, u)
        }
        return out
    }

    private suspend fun backgroundOf(ps: List<Part>, u: UsageIntervals): Int? {
        var sum = 0
        for (p in ps) {
            val b = if (partBackground.containsKey(p)) partBackground[p] else backgroundOf(p, u).also {
                partBackground[p] = it
            }
            sum += b ?: return null
        }
        return sum
    }

    /** null = unknown: too many lookups to load, lookups before usage coverage, or the deadline passed. */
    private suspend fun backgroundOf(p: Part, u: UsageIntervals): Int? {
        if (p.lookups > MAX_TIMES_PER_PAIR || p.first < u.coverageFrom || deadlinePassed()) return null
        val times = source.times(p.app, p.raw, MAX_TIMES_PER_PAIR + 1)
        if (times.size > MAX_TIMES_PER_PAIR || times.any { it < u.coverageFrom }) return null
        val ranges = foreground.getOrPut(p.app) { ForegroundIntervals.merge(u.byPackage[p.app].orEmpty()) }
        return times.count { !inAny(it, ranges) }
    }

    private fun evidence(background: Map<Key, Int?>): Map<Key, NetworkEvidence> = parts.mapValues { (key, ps) ->
        val lookups = ps.sumOf { it.lookups.toLong() }.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        NetworkEvidence(
            lookups = lookups,
            days = ps.flatMapTo(HashSet()) { it.days }.size,
            // Rows can arrive between counting and timing; never report more background than lookups.
            background = background[key]?.coerceAtMost(lookups),
            first = ps.minOf { it.first },
            last = ps.maxOf { it.last },
        )
    }

    private companion object {
        fun inAny(t: Long, ranges: List<LongRange>): Boolean {
            var lo = 0
            var hi = ranges.size - 1
            while (lo <= hi) {
                val mid = (lo + hi) ushr 1
                val r = ranges[mid]
                when {
                    t < r.first -> hi = mid - 1
                    t > r.last -> lo = mid + 1
                    else -> return true
                }
            }
            return false
        }
    }
}
