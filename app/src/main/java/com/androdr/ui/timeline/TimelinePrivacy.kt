package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.effectiveCorrelationId

/**
 * The privacy scan's place on the Timeline screen (spec 2026-11-10 §5.1, §5.3): its entries are information,
 * shown, searched and filtered like any entry, but never evidence and never exported.
 */
internal fun ForensicTimelineEvent.isPrivacyEntry(): Boolean = telemetrySource == TelemetrySource.PRIVACY_SCAN

/**
 * An item of the "By scan" list: a security scan's header, or the privacy scan's, placed by its date.
 */
sealed interface ScanListItem {
    data class Security(val group: ScanGroup) : ScanListItem

    /** The privacy scan whose entries the Timeline holds, at [at]. */
    data class Privacy(val at: Long) : ScanListItem
}

/**
 * Whether the privacy scan's header (at [at]) goes between [before] and [after] in the newest-first "By scan"
 * list: after every scan at or after it, before every older one. With no scans it stands alone.
 */
internal fun privacyHeaderBetween(before: ScanGroup?, after: ScanGroup?, at: Long): Boolean =
    (before == null || before.timestamp >= at) && (after == null || after.timestamp < at)

/**
 * "Linked evidence" for [event]: the [loaded] rows sharing its correlation key, itself excluded. A privacy
 * entry is never evidence, so it has none and is never listed (the package fallback would otherwise pair
 * an app's privacy entry with that app's findings).
 */
internal fun linkedEvidence(
    event: ForensicTimelineEvent,
    loaded: List<ForensicTimelineEvent>,
): List<ForensicTimelineEvent> {
    if (event.isPrivacyEntry()) return emptyList()
    val key = event.effectiveCorrelationId()
    if (key.isEmpty()) return emptyList()
    return loaded.filter { !it.isPrivacyEntry() && it.effectiveCorrelationId() == key && it.id != event.id }
}

/**
 * The details sheet's "Open in privacy results" for [event]: a privacy entry only, and only when the screen
 * can navigate ([open]). An app entry opens that app's privacy results; the scan entry, the privacy screen.
 */
internal fun openPrivacyAction(event: ForensicTimelineEvent, open: ((String?) -> Unit)?): (() -> Unit)? {
    if (open == null || !event.isPrivacyEntry()) return null
    val pkg = event.packageName.ifEmpty { null }
    return { open(pkg) }
}

/** A stable "By scan" list key: security scans by id, the privacy scan by its own name. */
internal fun ScanListItem.key(): String = when (this) {
    is ScanListItem.Security -> "scan_${group.scanId}"
    is ScanListItem.Privacy -> "privacy_scan"
}
