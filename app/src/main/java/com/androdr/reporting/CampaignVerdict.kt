package com.androdr.reporting

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.ioc.Campaign
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * One row of the MERCENARY SPYWARE CHECK. [detail] is the finding title or the IOC hit
 * (`<iocType> <indicator> (<family>), <yyyy-MM-dd>`); [earlierHit] is the second line an
 * EXPOSED row carries when the campaign also has an IOC hit older than the window.
 */
data class CampaignVerdict(
    val key: String,
    val label: String,
    val state: State,
    val detail: String,
    val earlierHit: String? = null,
) {
    /** Declaration order is row order. NOT_CHECKED is the import row; it never appears beside NOT_DETECTED. */
    enum class State { DETECTED, EXPOSED, EARLIER_HIT, NOT_DETECTED, NOT_CHECKED }
}

/** IOC hits older than this, measured back from the reference time, are "earlier hit only". */
internal const val CAMPAIGN_HIT_WINDOW_MS = 30L * 24 * 60 * 60 * 1000

private const val CAMPAIGN_TAG = "campaign."
private const val PATCH_LEVEL = "DEVICE_POSTURE"
private val CAMPAIGN_KEY = Regex("^[a-z0-9_-]{1,32}$")

/**
 * The time the 30-day window counts back from: the scan's own time for a live scan; for
 * an import, the latest imported timeline event, else the latest IOC observation in the
 * scan (the import's own log stats are not stored with the scan), else the scan time.
 */
internal fun campaignReferenceTime(scan: ScanResult, intrusionEvents: List<ForensicTimelineEvent>): Long {
    if (scan.source == TelemetrySource.LIVE_SCAN) return scan.timestamp
    return intrusionEvents.maxOfOrNull { it.startTimestamp }
        ?: scan.appRisks.mapNotNull { (it.evidence as? Evidence.IocMatch)?.observedAt }.filter { it > 0 }.maxOrNull()
        ?: scan.timestamp
}

/** A patch-level (`device_posture`) rule says the device is exposed, not infected (owner decision Q9-3). */
private fun Finding.isPatchLevel(ruleCategoryById: Map<String, String>): Boolean =
    ruleCategory.ifEmpty { ruleCategoryById[ruleId].orEmpty() } == PATCH_LEVEL

private data class CampaignHit(val time: Long, val text: String)

/**
 * The only place a campaign verdict is computed: the section rows and the summary's
 * "Campaign detections" / "Campaign exposure (unpatched)" lines both render from this list.
 *
 * Rows are the registry's campaigns plus any campaign key a rule tag names that the
 * registry does not know (rule content is hash-pinned); an IOC `campaign` the registry
 * does not know is ignored (spec section 3.1a). Aliases fold into their campaign's row.
 */
@Suppress("CyclomaticComplexMethod")
internal fun campaignVerdicts(
    scan: ScanResult,
    campaigns: List<Campaign>,
    referenceTime: Long,
    ruleCategoryById: Map<String, String>,
): List<CampaignVerdict> {
    val live = scan.source == TelemetrySource.LIVE_SCAN
    val keyByName = HashMap<String, String>()
    campaigns.forEach { c -> keyByName[c.key] = c.key }
    campaigns.forEach { c -> c.aliases.forEach { keyByName.putIfAbsent(it, c.key) } }
    val known = campaigns.map { it.key }.toSet()

    fun tagKeys(f: Finding): Set<String> = f.tags.filter { it.startsWith(CAMPAIGN_TAG) }
        .map { it.removePrefix(CAMPAIGN_TAG).lowercase() }
        .mapNotNull { keyByName[it] ?: it.takeIf(CAMPAIGN_KEY::matches) }
        .toSet()

    val unknownFromTags = scan.findings.flatMap { tagKeys(it) }.filter { it !in known }.distinct()
    val rows = campaigns.map { it.key to it.label } +
        unknownFromTags.map { key -> key to key.replaceFirstChar { it.uppercase() } }

    val dateFmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
    val hitsByKey = scan.appRisks.filter { it.triggered }
        .mapNotNull { it.evidence as? Evidence.IocMatch }
        .filter { it.campaign in known }
        .groupBy({ it.campaign }) { m ->
            // No observation time (package/cert/hash hits: present now) -> the reference time,
            // which is scan.timestamp on a live scan and the log's time on an import.
            val time = m.observedAt.takeIf { it > 0 } ?: referenceTime
            val family = if (m.family.isBlank()) "" else " (${m.family})"
            CampaignHit(time, "${m.iocType} ${m.matchedIndicator}$family, ${dateFmt.format(Date(time))}")
        }

    return rows.map { (key, label) ->
        val tagged = scan.findings.filter { it.triggered && key in tagKeys(it) }
        val (patchLevel, evidence) = tagged.partition { it.isPatchLevel(ruleCategoryById) }
        val (recent, old) = hitsByKey[key].orEmpty().partition { referenceTime - it.time <= CAMPAIGN_HIT_WINDOW_MS }
        val latestOld = old.maxByOrNull { it.time }
        when {
            evidence.isNotEmpty() -> CampaignVerdict(key, label, CampaignVerdict.State.DETECTED, evidence.first().title)
            recent.isNotEmpty() ->
                CampaignVerdict(key, label, CampaignVerdict.State.DETECTED, recent.maxBy { it.time }.text)
            live && patchLevel.isNotEmpty() -> CampaignVerdict(
                key, label, CampaignVerdict.State.EXPOSED, patchLevel.first().title, earlierHit = latestOld?.text,
            )
            latestOld != null -> CampaignVerdict(key, label, CampaignVerdict.State.EARLIER_HIT, latestOld.text)
            !live -> CampaignVerdict(key, label, CampaignVerdict.State.NOT_CHECKED, "")
            else -> CampaignVerdict(key, label, CampaignVerdict.State.NOT_DETECTED, "")
        }
    }.sortedBy { it.state.ordinal }
}

/**
 * The MERCENARY SPYWARE CHECK rows, then (live scans) the scope note that says what "not detected"
 * covers, then (live scans and imports) the could-not-run pointer and the failed-scanner line.
 */
internal fun StringBuilder.appendCampaignRows(
    verdicts: List<CampaignVerdict>,
    scan: ScanResult,
    referenceFromLog: Boolean,
) {
    val live = scan.source == TelemetrySource.LIVE_SCAN
    // What the 30-day window was measured from (campaignReferenceTime): on an import without
    // imported events it is the latest dated hit, so "the log's latest event" would be untrue.
    val before = when {
        live -> "this scan"
        referenceFromLog -> "the log's latest event"
        else -> "the latest dated hit in this import"
    }
    verdicts.forEach { v ->
        when (v.state) {
            CampaignVerdict.State.DETECTED -> appendLine("  [!!]  ${v.label}: DETECTED -- ${v.detail}")
            CampaignVerdict.State.EXPOSED -> {
                appendLine("  [!!]  ${v.label}: EXPOSED -- ${v.detail} (unpatched; not evidence of infection)")
                v.earlierHit?.let { appendLine("       also an earlier hit -- $it (over 30 days before this scan)") }
            }
            CampaignVerdict.State.EARLIER_HIT ->
                appendLine("  [--]  ${v.label}: earlier hit only -- ${v.detail} (over 30 days before $before)")
            CampaignVerdict.State.NOT_CHECKED ->
                appendLine("  [--]  ${v.label}: no hit in the imported log (device checks not run)")
            CampaignVerdict.State.NOT_DETECTED -> appendLine("  [OK]  ${v.label}: not detected")
        }
    }
    // The scope note is live-only (an import has no "not detected" row). The pointer and the
    // failed-check line apply to imports too: a failed attribution prefetch on an import
    // (IntrusionLogAnalysisResult.scannerErrors) means a campaign hit may be missing its key.
    if (live) appendLine("  \"not detected\" means none of the checks that ran in this scan matched.")
    val notRun = scan.scannerErrors.count { NotEvaluatedReason.fromSentinel(it.exception) != null }
    if (notRun > 0) {
        appendLine("  $notRun check(s) could not run -- see ${ReportFormatter.NOT_CHECKED_SECTION} below.")
    }
    if (scan.realFailureCount > 0) {
        appendLine("  ${scan.realFailureCount} scanner(s) failed on this scan; their checks did not run.")
    }
    appendLine()
}

/** The summary's campaign lines, from the same verdicts as the section. */
internal fun StringBuilder.appendCampaignSummary(verdicts: List<CampaignVerdict>) {
    if (verdicts.isEmpty()) return
    val detected = verdicts.filter { it.state == CampaignVerdict.State.DETECTED }.map { it.label }
    appendLine("    Campaign detections: ${detected.joinToString(", ").ifEmpty { "none" }}")
    val exposed = verdicts.filter { it.state == CampaignVerdict.State.EXPOSED }.map { it.label }
    if (exposed.isNotEmpty()) appendLine("    Campaign exposure (unpatched): ${exposed.joinToString(", ")}")
}
