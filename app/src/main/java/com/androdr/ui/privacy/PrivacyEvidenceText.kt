package com.androdr.ui.privacy

import android.content.res.Resources
import android.text.format.DateUtils
import com.androdr.R
import com.androdr.privacy.AppPrivacyRow
import com.androdr.privacy.Evidence
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.TrackerRow
import com.androdr.util.MAX_DISPLAY_NAME_CHARS
import com.androdr.util.displaySafe
import com.androdr.util.reportSafe
import java.net.URI

/**
 * Pure wording for privacy evidence. Facts only: network-only evidence is "looked up domains of this tracker",
 * never "carries"; an app that was not fully inspected never reads "none from the registry found".
 */
object PrivacyEvidenceText {
    private const val REASON_MAX = 120

    /** The evidence line for one tracker row of one app. */
    fun line(row: TrackerRow, res: Resources, now: Long = System.currentTimeMillis()): String = when (row.evidence) {
        Evidence.CODE -> res.getString(R.string.privacy_evidence_code)
        Evidence.NETWORK -> res.getString(R.string.privacy_evidence_network, networkDetail(row, res, now))
        Evidence.BOTH -> res.getString(R.string.privacy_evidence_both, networkDetail(row, res, now))
    }

    private fun networkDetail(row: TrackerRow, res: Resources, now: Long): String {
        val counts = res.getQuantityString(R.plurals.privacy_lookups, row.lookups, row.lookups) + " " +
            res.getQuantityString(R.plurals.privacy_days, row.lookupDays, row.lookupDays)
        val parts = mutableListOf(counts)
        parts += row.background?.let { res.getString(R.string.privacy_background, it) }
            ?: res.getString(R.string.privacy_background_unknown)
        row.lastSeen?.let {
            val relative = DateUtils.getRelativeTimeSpanString(it, now, DateUtils.MINUTE_IN_MILLIS).toString()
            parts += res.getString(R.string.privacy_last_seen, relative)
        }
        return parts.joinToString(", ")
    }

    /**
     * The per-app status line. "None from the registry" is only ever said of an [InspectOutcome.INSPECTED] app
     * with no trackers; a partly inspected or uninspectable app always says so, with its (sanitised) reason.
     */
    fun appStatus(row: AppPrivacyRow, registrySize: Int, res: Resources): String {
        val reason = row.reason?.let { reportSafe(it, REASON_MAX) }?.takeIf { it.isNotBlank() }
            ?: res.getString(R.string.privacy_reason_unknown)
        return when (row.outcome) {
            InspectOutcome.COULD_NOT_INSPECT -> res.getString(R.string.privacy_could_not_inspect, reason)
            InspectOutcome.PARTIAL -> res.getString(R.string.privacy_partial, reason)
            InspectOutcome.INSPECTED ->
                if (row.trackers.isEmpty()) {
                    res.getString(R.string.privacy_none_from_registry, registrySize)
                } else {
                    res.getQuantityString(R.plurals.privacy_tracker_count, row.trackers.size, row.trackers.size)
                }
        }
    }

    /**
     * An app's label through [displaySafe] (every script kept, controls and bidi overrides removed); the package
     * name (printable ASCII) only when nothing displayable remains.
     */
    fun appName(row: AppPrivacyRow): String = appName(row.appLabel, row.packageName)

    fun appName(label: String, packageName: String): String =
        displaySafe(label).ifBlank { reportSafe(packageName, MAX_DISPLAY_NAME_CHARS) }

    /** A tracker's name; falls back to its website host, then to "Tracker #id", when nothing displayable remains. */
    fun trackerName(name: String, website: String, id: Int): String =
        displaySafe(name).ifBlank {
            websiteHost(website)?.let { reportSafe(it, MAX_DISPLAY_NAME_CHARS) }?.ifBlank { null } ?: "Tracker #$id"
        }

    private fun parse(url: String): URI? = try {
        URI(url.trim())
    } catch (_: java.net.URISyntaxException) {
        null
    }

    /** The parsed, lower-cased host only; never the raw string. Null when there is no usable host. */
    fun websiteHost(url: String): String? =
        parse(url)?.host?.lowercase()?.takeIf { it.isNotBlank() }

    /**
     * The URL to open, only for an `https` address with a host and no userinfo (so
     * `https://trusted.example@evil.example` is never a link); null otherwise.
     */
    fun websiteLink(url: String): String? {
        val uri = parse(url) ?: return null
        val ok = uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank() && uri.rawUserInfo == null
        return if (ok) uri.toASCIIString() else null
    }
}
