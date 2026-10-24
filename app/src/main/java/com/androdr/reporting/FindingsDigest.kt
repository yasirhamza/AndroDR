package com.androdr.reporting

import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import java.util.IdentityHashMap

/**
 * Folds a scan's findings, streamed one at a time, into the findings the report needs (review I1,
 * I1-r): findings that would print the same are one entry with a multiplicity, and each entry keeps
 * only what the report reads, so memory is O(distinct printed lines), never O(findings).
 *
 * - **What an entry keeps.** A compact [Finding]: rule id, level, category, triggered, title,
 *   description, tags, remediation, guidance, implied flags and rule category — every string and
 *   list interned through one canonicalising map, so the per-rule text of 100k findings is held
 *   once — plus the evidence (IOC strings interned too) and only the [REPORTED_CONTEXT] subset of
 *   `matchContext` it can print. The decoded finding itself is dropped after [add].
 * - **The fold key** is that compact finding, with an IOC match's observation time zeroed. `domain`
 *   and `reason` take part only where the report prints them — the Blocked line of a live scan's
 *   IOC-domain finding — so 100k DDNS hits on distinct subdomains, or an import's DNS findings, fold
 *   per app. A correlation finding keeps its whole context (`member_count`).
 * - **Observation times.** Per window bucket (no time, older than the window, within it, after the
 *   scan) each entry keeps the latest time only — exactly what the campaign verdict and reference
 *   time read; the representative is rebuilt with it in [result].
 *
 * @param windowStart the campaign window's start ([campaignReferenceTime] − [CAMPAIGN_HIT_WINDOW_MS]).
 * @param scanTime the scan's own time (an observation after it never sets the reference time).
 * @param live whether the scan is a live scan (only then are Blocked lines, and so domains, printed).
 */
internal class FindingsDigest(
    private val windowStart: Long,
    private val scanTime: Long,
    private val live: Boolean = true,
) {
    /** One bucket: how many findings it stands for and their latest observation time. */
    private class Bucket(var time: Long, var count: Int = 1)

    private val folds = LinkedHashMap<Finding, Array<Bucket?>>()
    private val strings = HashMap<String, String>()
    private val lists = HashMap<List<String>, List<String>>()

    fun add(f: Finding) {
        val time = (f.evidence as? Evidence.IocMatch)?.observedAt ?: 0L
        val buckets = folds.getOrPut(compact(f)) { arrayOfNulls(BUCKETS) }
        val i = bucketOf(time)
        val b = buckets[i]
        if (b == null) {
            buckets[i] = Bucket(time)
        } else {
            b.count++
            if (time > b.time) b.time = time
        }
    }

    /** How many entries the digest holds (distinct printed findings), for tests and diagnostics. */
    val size: Int get() = folds.size

    /** The folded findings in first-appearance order, with how many findings each stands for. */
    fun result(): FindingsView.Folded {
        val out = ArrayList<Finding>()
        val counts = IdentityHashMap<Finding, Int>()
        for ((key, buckets) in folds) for (b in buckets) if (b != null) {
            val ioc = key.evidence as? Evidence.IocMatch
            val rep = if (ioc == null) key else key.copy(evidence = ioc.copy(observedAt = b.time))
            out += rep
            counts[rep] = b.count
        }
        return FindingsView.Folded(out, counts)
    }

    private fun bucketOf(time: Long): Int = when {
        time <= 0L -> NO_TIME
        time > scanTime -> AFTER_SCAN
        time < windowStart -> OLDER
        else -> WITHIN
    }

    private fun s(value: String): String = strings.getOrPut(value) { value }

    private fun l(value: List<String>): List<String> =
        if (value.isEmpty()) emptyList() else lists.getOrPut(value) { value.map(::s) }

    /** What the report reads of [f], interned, with an IOC match's observation time zeroed. */
    private fun compact(f: Finding): Finding {
        val ioc = f.evidence as? Evidence.IocMatch
        val evidence = if (ioc == null) {
            f.evidence
        } else {
            Evidence.IocMatch(s(ioc.matchedIndicator), s(ioc.iocType), s(ioc.source), s(ioc.family),
                s(ioc.category), s(ioc.campaign), s(ioc.reference), 0L)
        }
        // A copy, not a new Finding: findings are constructed only by the rule engines (#84/#136). Its
        // level stays the decoded instance (one short string per entry); nothing here changes it.
        return f.copy(
            ruleId = s(f.ruleId), title = s(f.title), description = s(f.description),
            tags = l(f.tags), remediation = l(f.remediation), iconHint = "", safeTitle = "", guidance = s(f.guidance),
            evidence = evidence, matchContext = context(f, ioc), impliesFlags = l(f.impliesFlags),
            ruleCategory = s(f.ruleCategory), service = "", ordinal = -1, recordId = null,
        )
    }

    private fun context(f: Finding, ioc: Evidence.IocMatch?): Map<String, String> {
        if (f.category == FindingCategory.CORRELATION) {
            return f.matchContext.entries.associate { s(it.key) to s(it.value) }
        }
        // Domain and reason are printed only on a live scan's IOC-domain finding (its Blocked line).
        val blocked = live && ioc?.iocType == "domain"
        val out = LinkedHashMap<String, String>()
        for ((k, v) in f.matchContext) {
            if (k in PACKAGE_CONTEXT || (blocked && k in BLOCKED_CONTEXT)) out[s(k)] = s(v)
        }
        return out
    }

    companion object {
        /** The `matchContext` keys any report section prints. */
        val REPORTED_CONTEXT: Set<String> get() = PACKAGE_CONTEXT + BLOCKED_CONTEXT

        /** Printed for every finding: the app group's key and header. */
        private val PACKAGE_CONTEXT = setOf("package_name", "source_package", "app_name", "apk_hash", "cert_hash")

        /** Printed only in a live scan's Blocked line for an IOC-domain finding. */
        private val BLOCKED_CONTEXT = setOf("domain", "reason")

        private const val NO_TIME = 0
        private const val OLDER = 1
        private const val WITHIN = 2
        private const val AFTER_SCAN = 3
        private const val BUCKETS = 4
    }
}
