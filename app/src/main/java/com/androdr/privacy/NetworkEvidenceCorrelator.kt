package com.androdr.privacy

import com.androdr.data.db.DomainLookupCount
import com.androdr.privacy.model.TrackerSet

/**
 * Correlates the attributed DNS log with the tracker registry. The log is app-writable in effect (any app can
 * flood it with lookups), so every step is bounded per installed app: a flooding app can only hide its own
 * network evidence, never another app's. See [CorrelationRun] for the mechanics.
 */
object NetworkEvidenceCorrelator {
    data class Key(val packageName: String, val trackerId: Int)

    /** [background] null = unknown (no usage access, lookups before usage coverage, or not timed). */
    data class NetworkEvidence(val lookups: Int, val days: Int, val background: Int?, val first: Long, val last: Long)

    data class Correlation(val evidence: Map<Key, NetworkEvidence>, val truncated: Boolean)

    /** The runner adapts DnsEventDao to this; tests use a fake. */
    interface DnsSource {
        suspend fun domainsAfter(app: String, afterDomain: String, limit: Int): List<String>
        suspend fun count(app: String, rawDomain: String): DomainLookupCount
        suspend fun times(app: String, rawDomain: String, limit: Int): List<Long>
    }

    /**
     * Per installed app, in packageName order, each with its own quota:
     * Phase 1 — match: page the app's distinct raw domains [PAGE_SIZE] at a time, at most [MAX_DOMAINS_PER_APP];
     * normalise each and match it against [registry] once (memo per normalised domain; once the memo holds
     * [MAX_MEMO] entries, further domains are matched without being memoised — never skipped).
     * Phase 2 — count: [DnsSource.count] for the app's matched raw domains, at most [MAX_MATCHED_PER_APP]; a pair
     * whose count comes back with lookups = 0 (pruned by age between paging and counting) is skipped.
     * Either per-app quota reached with work left, or [MAX_MATCHED_PAIRS] overall -> truncated.
     * Phase 3 — background: [DnsSource.times] with limit [MAX_TIMES_PER_PAIR] + 1 for the [MAX_TIMED_PAIRS] pairs
     * with the most lookups; a pair beyond that cap, or with more than [MAX_TIMES_PER_PAIR] lookups, gets
     * background = null. [expired] is checked before each page and each count/times call; when true, stop and
     * return truncated = true with the evidence so far (untimed pairs have background = null).
     */
    suspend fun correlate(
        source: DnsSource,
        registry: TrackerSet,
        installed: Set<String>,
        usage: UsageIntervals?,
        expired: () -> Boolean,
    ): Correlation = CorrelationRun(source, registry, usage, expired).run(installed.sorted())

    /** Lower-cased, trailing dot removed: the form [TrackerSet.matchDomain] expects. */
    fun normalise(raw: String): String = raw.lowercase(java.util.Locale.ROOT).removeSuffix(".")

    const val PAGE_SIZE = 1_000
    const val MAX_DOMAINS_PER_APP = 5_000
    const val MAX_MATCHED_PER_APP = 200
    const val MAX_MEMO = 100_000
    const val MAX_MATCHED_PAIRS = 20_000
    const val MAX_TIMED_PAIRS = 5_000
    const val MAX_TIMES_PER_PAIR = 10_000
}
