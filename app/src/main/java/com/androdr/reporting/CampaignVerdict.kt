package com.androdr.reporting

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
    /** null = no `detected_by` for this campaign, or an import: render today's row; empty = patch level only. */
    val coverage: List<ServiceStatus>? = null,
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
 * an import, [latestImportedEvent] (the latest exact event time among the import's own stored
 * records, never one dated after the import: the caller bounds it), else the latest IOC
 * observation in the scan that is not dated after the import (a future-dated one would push
 * genuine hits out of the window), else the scan time.
 */
internal fun campaignReferenceTime(scan: ScanResult, latestImportedEvent: Long?): Long {
    if (scan.source == TelemetrySource.LIVE_SCAN) return scan.timestamp
    return latestImportedEvent
        ?: scan.appRisks.mapNotNull { (it.evidence as? Evidence.IocMatch)?.observedAt }
            .filter { it > 0 && it <= scan.timestamp }.maxOrNull()
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
    ruleScopes: Map<String, RuleScope>,
): List<CampaignVerdict> {
    val live = scan.source == TelemetrySource.LIVE_SCAN
    val keyByName = HashMap<String, String>()
    campaigns.forEach { c -> keyByName[c.key] = c.key }
    campaigns.forEach { c -> c.aliases.forEach { keyByName.putIfAbsent(it, c.key) } }
    val known = campaigns.map { it.key }.toSet()
    val detectedByKey = campaigns.associate { it.key to it.detectedBy }
    fun coverageOf(key: String): List<ServiceStatus>? = if (!live) null
        else detectedByKey[key]?.let { campaignCoverage(it, key, scan.scannerErrors, ruleScopes) }

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
        val coverage = coverageOf(key)
        fun verdict(state: CampaignVerdict.State, detail: String, earlierHit: String? = null) =
            CampaignVerdict(key, label, state, detail, earlierHit, coverage)
        when {
            evidence.isNotEmpty() -> verdict(CampaignVerdict.State.DETECTED, evidence.first().title)
            recent.isNotEmpty() -> verdict(CampaignVerdict.State.DETECTED, recent.maxBy { it.time }.text)
            live && patchLevel.isNotEmpty() ->
                verdict(CampaignVerdict.State.EXPOSED, patchLevel.first().title, earlierHit = latestOld?.text)
            latestOld != null -> verdict(CampaignVerdict.State.EARLIER_HIT, latestOld.text)
            !live -> verdict(CampaignVerdict.State.NOT_CHECKED, "")
            else -> verdict(CampaignVerdict.State.NOT_DETECTED, "")
        }
    }.sortedBy { it.state.ordinal }
}

private val SERVICE_WORDS = mapOf(
    "dns_monitor" to "DNS lookups", "app_scanner" to "installed apps", "file_scanner" to "files",
    "device_auditor" to "device settings", "process_monitor" to "running processes",
    "accessibility_audit" to "accessibility services", "receiver_audit" to "app receivers",
    "appops_audit" to "app permissions in use",
)
private fun words(service: String) = SERVICE_WORDS[service] ?: service

private const val FIX_DNS = "Turn on DNS monitoring, use the phone as usual, then scan again."
private const val FIX_FAILED = "Scan again; if it keeps failing, export the report and send it to us."
private const val FIX_LISTS = "Scan again in a few minutes."
private const val FIX_IMPORT = "Import one to check this."
private const val FIX_UPDATE = "Update the app."
private const val FIX_RELOAD = "Scan again later; if it persists, update the app."
private const val NO_INFECTION_CHECK = "no infection check exists for a live scan; patch level only"

/** One clause and its fix (or null) for a service that was not fully checked. Exhaustive: no `else`. */
private fun clause(s: ServiceStatus): Pair<String, String?> {
    val w = words(s.service)
    return when (s.coverage) {
        ServiceCoverage.BLIND -> when (s.reason) {
            BlindReason.DNS_OFF ->
                "$w not monitored (DNS monitoring was off; only lookups recorded earlier were checked)" to FIX_DNS
            BlindReason.UNKNOWN_SERVICE -> "$w not checked (this app version does not know that check)" to FIX_UPDATE
            BlindReason.ATTRIBUTION_FAILED ->
                "$w checked, but hits could not be matched to campaigns (that step failed on this scan)" to FIX_FAILED
            BlindReason.CHECK_FAILED, null -> "$w not checked (that check failed on this scan)" to FIX_FAILED
        }
        ServiceCoverage.PARTLY_UNREADABLE -> "$w only partly checked (some paths could not be read)" to null
        ServiceCoverage.PARTLY_SKIPPED ->
            "$w only partly checked (some of its rules could not run on this app version)" to FIX_UPDATE
        ServiceCoverage.BUILT_IN_LISTS_ONLY ->
            "$w checked against the built-in list only (threat lists had not finished loading)" to FIX_LISTS
        ServiceCoverage.LISTS_UNKNOWN ->
            "$w checked, but it is not known whether the threat lists had loaded" to FIX_LISTS
        ServiceCoverage.NO_DETECTOR -> "$w not checked (the rule that detects it was not loaded)" to FIX_RELOAD
        ServiceCoverage.NEEDS_IMPORT -> "$w need a bug report or intrusion log" to FIX_IMPORT
        ServiceCoverage.CHECKED -> "" to null
    }
}

/** The row's state text and its distinct fixes, in clause order. */
internal fun coverageSummary(coverage: List<ServiceStatus>): Pair<String, List<String>> {
    if (coverage.isEmpty()) return NO_INFECTION_CHECK to emptyList()
    val checked = coverage.filter { it.coverage == ServiceCoverage.CHECKED }
    if (checked.size == coverage.size) return "not detected" to emptyList()
    val missing = coverage.filter { it.coverage != ServiceCoverage.CHECKED }.map(::clause)
    val parts = buildList {
        if (checked.isNotEmpty()) add("no hit in ${checked.joinToString(" and ") { words(it.service) }}")
        addAll(missing.map { it.first })
    }
    return parts.joinToString("; ") to missing.mapNotNull { it.second }.distinct()
}

private fun ReportOut.appendFixes(fixes: List<String>) {
    if (fixes.isNotEmpty()) appendLine("        ${fixes.joinToString(" ")}")
}

/**
 * The MERCENARY SPYWARE CHECK rows, then (live scans) the scope note that says what "not detected"
 * covers, then (live scans and imports) the could-not-run pointer and the failed-scanner line.
 */
internal fun ReportOut.appendCampaignRows(
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
                val summary = v.coverage?.let(::coverageSummary)
                val suffix = summary?.let { "; infection check: ${it.first}" }.orEmpty()
                appendLine("  [!!]  ${v.label}: EXPOSED -- ${v.detail} (unpatched; not evidence of infection)$suffix")
                v.earlierHit?.let { appendLine("       also an earlier hit -- $it (over 30 days before this scan)") }
                summary?.let { appendFixes(it.second) }
            }
            CampaignVerdict.State.EARLIER_HIT ->
                appendLine("  [--]  ${v.label}: earlier hit only -- ${v.detail} (over 30 days before $before)")
            CampaignVerdict.State.NOT_CHECKED ->
                appendLine("  [--]  ${v.label}: no hit in the imported log (device checks not run)")
            CampaignVerdict.State.NOT_DETECTED -> {
                val summary = v.coverage?.let(::coverageSummary)
                if (summary == null || summary.first == "not detected") {
                    appendLine("  [OK]  ${v.label}: not detected")
                } else {
                    appendLine("  [--]  ${v.label}: ${summary.first}")
                    appendFixes(summary.second)
                }
            }
        }
    }
    // Rows with their own coverage say what "not detected" covered; only legacy rows (no detected_by) need the
    // note. The pointer and the failed-check line apply to imports too: a failed attribution prefetch on an
    // import (IntrusionLogAnalysisResult.scannerErrors) means a campaign hit may be missing its key.
    if (live && verdicts.any { it.state == CampaignVerdict.State.NOT_DETECTED && it.coverage == null }) {
        appendLine("  \"not detected\" means none of the checks that ran in this scan matched.")
    }
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
internal fun ReportOut.appendCampaignSummary(verdicts: List<CampaignVerdict>) {
    if (verdicts.isEmpty()) return
    val detected = verdicts.filter { it.state == CampaignVerdict.State.DETECTED }.map { it.label }
    appendLine("    Campaign detections: ${detected.joinToString(", ").ifEmpty { "none" }}")
    val exposed = verdicts.filter { it.state == CampaignVerdict.State.EXPOSED }.map { it.label }
    if (exposed.isNotEmpty()) appendLine("    Campaign exposure (unpatched): ${exposed.joinToString(", ")}")
}
