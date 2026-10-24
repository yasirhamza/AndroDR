package com.androdr.reporting

import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import java.util.IdentityHashMap

/**
 * Folds a scan's findings, streamed one at a time, into the findings the report needs (review I1):
 * every finding the report would render differently is kept, and findings that would render the
 * same are folded into one representative with a multiplicity, so the report reads a 100k-finding
 * import without holding it. Memory is bounded by what the report prints (its distinct titles,
 * indicators, packages), not by how many findings the scan holds.
 *
 * Two findings render the same when they agree on everything [ReportFormatter], [campaignVerdicts]
 * and [dnsIocRows] read: rule, level, category, triggered, title, description, tags, remediation,
 * guidance, implied flags, rule category, the evidence (an IOC match without its observation time),
 * and the `matchContext` keys the report prints ([REPORTED_CONTEXT]; a correlation finding keeps its
 * whole context). An IOC match's observation time matters only through the campaign window, so each
 * fold keeps, per window bucket (no time, older than the window, within it, after the scan), the
 * finding with the latest time — exactly what the campaign verdict and reference time read.
 *
 * @param windowStart the campaign window's start ([campaignReferenceTime] − [CAMPAIGN_HIT_WINDOW_MS]).
 * @param scanTime the scan's own time (an observation after it never sets the reference time).
 */
internal class FindingsDigest(private val windowStart: Long, private val scanTime: Long) {
    private class Bucket(var finding: Finding, var count: Int = 1)

    private val folds = LinkedHashMap<Finding, Array<Bucket?>>()

    fun add(f: Finding) {
        val buckets = folds.getOrPut(keyOf(f)) { arrayOfNulls(BUCKETS) }
        val time = (f.evidence as? Evidence.IocMatch)?.observedAt ?: 0L
        val i = bucketOf(time)
        val b = buckets[i]
        when {
            b == null -> buckets[i] = Bucket(f)
            else -> {
                b.count++
                if (time > ((b.finding.evidence as? Evidence.IocMatch)?.observedAt ?: 0L)) b.finding = f
            }
        }
    }

    /** The folded findings in first-appearance order, with how many findings each stands for. */
    fun result(): FindingsView.Folded {
        val out = ArrayList<Finding>()
        val counts = IdentityHashMap<Finding, Int>()
        for (buckets in folds.values) for (b in buckets) if (b != null) {
            out += b.finding
            counts[b.finding] = b.count
        }
        return FindingsView.Folded(out, counts)
    }

    private fun bucketOf(time: Long): Int = when {
        time <= 0L -> NO_TIME
        time > scanTime -> AFTER_SCAN
        time < windowStart -> OLDER
        else -> WITHIN
    }

    private fun keyOf(f: Finding): Finding = f.copy(
        matchContext = if (f.category == FindingCategory.CORRELATION) f.matchContext
        else f.matchContext.filterKeys { it in REPORTED_CONTEXT },
        evidence = (f.evidence as? Evidence.IocMatch)?.copy(observedAt = 0L) ?: f.evidence,
        service = "", ordinal = -1, recordId = null,
    )

    companion object {
        /** The `matchContext` keys any report section prints. */
        val REPORTED_CONTEXT = setOf(
            "package_name", "source_package", "app_name", "apk_hash", "cert_hash", "domain", "reason",
        )

        private const val NO_TIME = 0
        private const val OLDER = 1
        private const val WITHIN = 2
        private const val AFTER_SCAN = 3
        private const val BUCKETS = 4
    }
}
