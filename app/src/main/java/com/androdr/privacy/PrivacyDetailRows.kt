package com.androdr.privacy

import com.androdr.data.model.PrivacyCodeDetail
import com.androdr.data.model.PrivacyDomainDetail
import com.androdr.privacy.NetworkEvidenceCorrelator.DomainEvidence
import com.androdr.privacy.model.CodeMatch

/**
 * Builds the detail rows a scan stores for the details view. Pure. The text comes from an app's code
 * or its DNS lookups, both under the app's control, so every stored name is bounded: at most
 * [MAX_PACKAGES_PER_TRACKER] package names per app + tracker (shared across that tracker's
 * signatures), [MAX_PACKAGES_PER_APP] per app, and each name [cut] to [MAX_TEXT_CHARS] with a
 * visible mark. True counts are always kept.
 */
internal object PrivacyDetailRows {
    const val MAX_PACKAGES_PER_TRACKER = 200
    const val MAX_PACKAGES_PER_APP = 2_000

    /** The longest host the matcher accepts (253) plus the trailing dot the normaliser removes. */
    const val MAX_TEXT_CHARS = 254
    const val CUT_MARK = "…"

    /** [text] unchanged up to [MAX_TEXT_CHARS] code points; longer, its first [MAX_TEXT_CHARS] and [CUT_MARK]. */
    fun cut(text: String): String =
        if (text.codePointCount(0, text.length) <= MAX_TEXT_CHARS) {
            text
        } else {
            text.substring(0, text.offsetByCodePoints(0, MAX_TEXT_CHARS)) + CUT_MARK
        }

    /** One row per match, in the given order; names are stored until the tracker's or the app's budget runs out. */
    fun code(scanId: Long, packageName: String, matches: List<CodeMatch>): List<PrivacyCodeDetail> {
        var appLeft = MAX_PACKAGES_PER_APP
        val trackerLeft = HashMap<Int, Int>()
        return matches.map { m ->
            val left = minOf(appLeft, trackerLeft[m.tracker.id] ?: MAX_PACKAGES_PER_TRACKER)
            val kept = m.packages.take(left)
            appLeft -= kept.size
            trackerLeft[m.tracker.id] = (trackerLeft[m.tracker.id] ?: MAX_PACKAGES_PER_TRACKER) - kept.size
            PrivacyCodeDetail(
                scanId = scanId,
                packageName = packageName,
                trackerId = m.tracker.id,
                kind = m.kind.name,
                signature = cut(m.signature),
                packageCount = m.packages.size,
                packages = kept.joinToString("\n") { cut(it) },
            )
        }
    }

    /** One row per counted domain and owning tracker; the domain as recorded, [cut]. */
    fun domains(scanId: Long, domains: List<DomainEvidence>): List<PrivacyDomainDetail> = domains.map { d ->
        PrivacyDomainDetail(
            scanId = scanId,
            packageName = d.key.packageName,
            trackerId = d.key.trackerId,
            domain = cut(d.domain),
            kind = d.kind.name,
            signature = cut(d.signature),
            lookups = d.lookups,
            lookupDays = d.days,
            background = d.background,
            firstSeen = d.first,
            lastSeen = d.last,
        )
    }

    /** The stored package names of [row]; empty when every name was left out by the app's budget. */
    fun packagesOf(row: PrivacyCodeDetail): List<String> =
        if (row.packages.isEmpty()) emptyList() else row.packages.split('\n')
}
