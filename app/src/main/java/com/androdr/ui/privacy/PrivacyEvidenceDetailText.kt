package com.androdr.ui.privacy

import android.content.res.Resources
import com.androdr.R
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyScan
import com.androdr.privacy.DomainLine
import com.androdr.privacy.model.SignatureKind
import com.androdr.util.displaySafe

/**
 * Pure wording for the details view of one tracker in one app. Package names, domains and signatures
 * come from the app's code, its lookups or the tracker list; they reach the screen only through [shown].
 */
object EvidenceDetailText {
    /** A full domain plus the stored cut mark ("…"), so stored text is never cut a second time. */
    private const val SHOWN_MAX = 255
    private const val HASH_HEAD = 4
    private const val HASH_TAIL = 2

    /** Every script kept; controls, bidi overrides and zero-width characters removed. */
    fun shown(text: String): String = displaySafe(text, SHOWN_MAX)

    fun kindLabel(kind: SignatureKind): Int = when (kind) {
        SignatureKind.CODE_PREFIX -> R.string.privacy_kind_code_prefix
        SignatureKind.CODE_SEGMENT -> R.string.privacy_kind_code_segment
        SignatureKind.DOMAIN_SUFFIX -> R.string.privacy_kind_domain_suffix
        SignatureKind.DOMAIN_LABEL -> R.string.privacy_kind_domain_label
        SignatureKind.DOMAIN_PATTERN -> R.string.privacy_kind_domain_pattern
    }

    /** The first four and last two characters of the list's hash; null when there is none to show. */
    fun shortHash(sha: String): String? {
        val s = sha.trim()
        return if (s.length < HASH_HEAD + HASH_TAIL) null else s.take(HASH_HEAD) + "…" + s.takeLast(HASH_TAIL)
    }

    /** "… and N more" when [total] packages matched but only [stored] names were kept; null otherwise. */
    fun more(stored: Int, total: Int, res: Resources): String? {
        val left = total - stored
        return if (left > 0) res.getQuantityString(R.plurals.privacy_evidence_more, left, left) else null
    }

    fun signatureLine(kind: SignatureKind, signature: String, res: Resources): String =
        res.getString(R.string.privacy_evidence_signature, shown(signature), res.getString(kindLabel(kind)))

    fun matchedLine(kind: SignatureKind, signature: String, res: Resources): String =
        res.getString(R.string.privacy_evidence_matched, shown(signature), res.getString(kindLabel(kind)))

    /** Lookups, days, background (or "unknown", never zero), first and last, for one domain. */
    fun domainCounts(d: DomainLine, res: Resources, formatTime: (Long) -> String): String = listOf(
        res.getQuantityString(R.plurals.privacy_lookups, d.lookups, d.lookups) + " " +
            res.getQuantityString(R.plurals.privacy_days, d.days, d.days),
        d.background?.let { res.getString(R.string.privacy_background, it) }
            ?: res.getString(R.string.privacy_background_unknown),
        res.getString(R.string.privacy_evidence_first_last, formatTime(d.first), formatTime(d.last)),
    ).joinToString(", ")

    /** The Exodus page of a list entry; only for a positive entry number. */
    fun exodusLink(id: Int): String? =
        if (id > 0) "https://reports.exodus-privacy.eu.org/en/trackers/$id/" else null

    /** True when the scan's network step was cut short or failed: its domain list may be incomplete. */
    fun networkIncomplete(scan: PrivacyScan): Boolean =
        scan.networkStatus == NetworkStatus.TRUNCATED.name || scan.networkStatus == NetworkStatus.FAILED.name

    /** The notice the privacy screen shows for a cut-short or failed network step; null otherwise. */
    fun networkNotice(scan: PrivacyScan): Int? = when (scan.networkStatus) {
        NetworkStatus.TRUNCATED.name -> R.string.privacy_network_truncated
        NetworkStatus.FAILED.name -> R.string.privacy_network_failed
        else -> null
    }

    /** The coverage statement the privacy screen shows; null when the network step did not count lookups. */
    fun coverage(scan: PrivacyScan, res: Resources): String? {
        val counted = scan.networkStatus == NetworkStatus.COMPLETE.name ||
            scan.networkStatus == NetworkStatus.TRUNCATED.name
        return when {
            !counted -> null
            scan.dnsCoverageDays == 0 -> res.getString(R.string.privacy_no_monitor)
            else -> res.getQuantityString(R.plurals.privacy_network_coverage, scan.dnsCoverageDays, scan.dnsCoverageDays)
        }
    }

    fun window(scan: PrivacyScan, res: Resources, formatTime: (Long) -> String): String =
        res.getString(R.string.privacy_evidence_window, formatTime(scan.dnsWindowStart), formatTime(scannedAt(scan)))

    /** "Privacy scan of <date> · tracker list: N trackers (a41c…9e)". */
    fun footer(scan: PrivacyScan, res: Resources, formatTime: (Long) -> String): String {
        val at = formatTime(scannedAt(scan))
        return shortHash(scan.registrySha256)?.let {
            res.getString(R.string.privacy_evidence_footer_hash, at, scan.registrySize, it)
        } ?: res.getString(R.string.privacy_evidence_footer, at, scan.registrySize)
    }

    private fun scannedAt(scan: PrivacyScan): Long = scan.finishedAt ?: scan.startedAt
}
