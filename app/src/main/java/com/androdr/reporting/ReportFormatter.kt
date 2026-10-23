package com.androdr.reporting

import android.os.Build
import com.androdr.data.db.ServiceSummary
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import com.androdr.sigma.LiveRecordBuilders
import java.io.Writer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Escapes `\` and every character in Unicode categories Cc, Cf, Zl, Zp, Co, Cn and Cs (lone
 * surrogates) as `\uXXXX` (spec §7), so no device-controlled string can emit a raw line break, a
 * bidi override, or an escape that reads ambiguously. A supplementary character in one of those
 * categories becomes its two escaped UTF-16 units; a valid surrogate pair otherwise passes through.
 * Cn follows the runtime's Unicode tables, so a character assigned in a newer Unicode version is
 * escaped on an older device (fail-safe; the same text can escape differently across devices).
 */
fun escapeForReport(s: String): String {
    var i = 0
    while (i < s.length && !needsEscapeAt(s, i)) i += unitWidth(s, i)
    if (i == s.length) return s
    val out = StringBuilder(s.length + ESCAPE_HEADROOM).append(s, 0, i)
    while (i < s.length) {
        val width = unitWidth(s, i)
        if (needsEscapeAt(s, i)) {
            for (j in i until i + width) out.append("\\u").append(String.format(Locale.US, "%04X", s[j].code))
        } else {
            out.append(s, i, i + width)
        }
        i += width
    }
    return out.toString()
}

/** 2 when a valid surrogate pair starts at [i], else 1. */
private fun unitWidth(s: String, i: Int): Int =
    if (Character.isHighSurrogate(s[i]) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) 2 else 1

/** Whether the character (or surrogate pair) starting at [i] must be escaped. */
private fun needsEscapeAt(s: String, i: Int): Boolean {
    val c = s[i]
    if (c == '\\') return true
    // Pairs are stepped over whole, so a low surrogate reached here has no high one before it: lone (Cs).
    val cp = if (unitWidth(s, i) == 2) Character.toCodePoint(c, s[i + 1]) else c.code
    return when (Character.getType(cp).toByte()) {
        Character.CONTROL, Character.FORMAT, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR,
        Character.PRIVATE_USE, Character.UNASSIGNED, Character.SURROGATE -> true
        else -> false
    }
}

private const val ESCAPE_HEADROOM = 16

/**
 * The report's output: every line is passed through [escapeForReport] as it is written, so the
 * findings section, the telemetry records (field keys, values, and values nested in lists and
 * maps) and the log are escaped by construction, with nothing to remember at each call site.
 * Only the line breaks the report itself writes are raw.
 */
internal class ReportOut(private val out: Appendable) {
    fun appendLine(text: CharSequence): ReportOut {
        out.append(escapeForReport(text.toString())).append('\n')
        return this
    }

    fun appendLine(): ReportOut {
        out.append('\n')
        return this
    }

    /** A section heading between two thin rules. */
    fun section(title: String) {
        appendLine(THIN)
        appendLine("  $title")
        appendLine(THIN)
    }

    private companion object {
        const val THIN = "------------------------------------------------------------"
    }
}

/**
 * Produces the plaintext security report for one scan. Its telemetry sections stream that scan's
 * own stored records ([StoredTelemetrySource]); nothing is held in memory but the findings and a
 * batch of records. [ReportExporter] is the only caller (spec §7, R2).
 */
object ReportFormatter {

    /** What the findings sections need beyond the findings, read from this scan's own telemetry. */
    private class FindingsContext(
        val appCount: String,
        val displayNames: Map<String, String>,
        val dnsIocRows: List<String>,
        val verdicts: List<CampaignVerdict>,
        val referenceFromLog: Boolean,
    )

    @Suppress("LongParameterList") // the report's fixed inputs (spec §7 / plan B1 signature)
    suspend fun writeScanReport(
        out: Writer,
        scan: ScanResult,
        findings: FindingsView,
        logLines: List<String>,
        telemetry: StoredTelemetrySource,
        mode: ExportMode,
        versionName: String,
    ) {
        // Phase B: the findings are the scan's own; every helper reads them from the scan.
        val s = scan.copy(findings = findings.findings)
        val o = ReportOut(out)
        val includeFindings = mode != ExportMode.TELEMETRY_ONLY
        val includeTelemetry = mode != ExportMode.FINDINGS_ONLY
        val services = telemetry.services(s.id)
        o.appendHeader(s, mode, versionName)
        if (includeFindings) {
            // One overall-risk calculation, shared with every UI surface (dashboard,
            // history). This header used to run a second ladder that scored the first word
            // of each rule's prose `display.guidance` instead of its severity (#332).
            // Device posture still caps at MEDIUM -- that rule lives in overallRiskLevel,
            // which is where #70 intended it. Pinned by OverallRiskConsistencyTest.
            o.appendLine("  OVERALL RISK: ${s.overallRiskLevel.name}")
            o.appendLine()
            o.section("FINDINGS SECTION")
            o.appendFindingsSections(s, findingsContext(s, findings, services, telemetry))
            // Intentionally inside the includeFindings branch: a capability skip is a
            // caveat ON the findings ("this list is missing these rules"), so it rides
            // the same flag -- a telemetry-only export has no findings list to caveat.
            o.appendNotChecked(s)
        }
        if (includeTelemetry) {
            o.section("TELEMETRY SECTION")
            o.appendStoredTelemetry(s, services, telemetry)
            o.appendLog(logLines)
        }
        o.appendLine()
        o.appendLine(RULE)
        o.appendLine("  End of report / AndroDR / scan id ${s.id}")
        o.appendLine(RULE)
    }

    private fun ReportOut.appendHeader(scan: ScanResult, mode: ExportMode, versionName: String) {
        val timestampFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        appendLine(RULE)
        appendLine("  AndroDR Security Report")
        appendLine("  Format    : v${ReportExporter.EXPORT_FORMAT_VERSION} (mode=${mode.name})")
        appendLine("  Version   : $versionName")
        appendLine("  Generated : ${timestampFmt.format(Date())}")
        appendLine("  Scan time : ${timestampFmt.format(Date(scan.timestamp))}")
        appendLine("  Android   : ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("  Device    : ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("  Patch     : ${Build.VERSION.SECURITY_PATCH}")
        appendLine(RULE)
        appendLine()
    }

    /**
     * Reads what the findings sections need from this scan's own records only: the app count and
     * display names from its `app_scanner` records, the tunnel's IOC reasons from its `dns_monitor`
     * records (only when no finding carries domain IOC evidence), and an import's latest event.
     */
    private suspend fun findingsContext(
        scan: ScanResult,
        findings: FindingsView,
        services: List<ServiceSummary>,
        telemetry: StoredTelemetrySource,
    ): FindingsContext {
        val appRecords = services.firstOrNull { it.service == LiveRecordBuilders.APP_SCANNER }
        val displayNames = HashMap<String, String>()
        if (appRecords != null && scan.appRisks.any { it.triggered }) {
            telemetry.forEach(scan.id, LiveRecordBuilders.APP_SCANNER) { r ->
                val pkg = r.fields?.get("package_name") as? String
                val name = r.fields?.get("app_name") as? String
                if (!pkg.isNullOrEmpty() && !name.isNullOrEmpty()) displayNames[pkg] = name
            }
        }
        val reasons = LinkedHashSet<String>()
        val hasDomainEvidence = scan.appRisks.any {
            it.triggered && (it.evidence as? Evidence.IocMatch)?.iocType == "domain"
        }
        if (!hasDomainEvidence && services.any { it.service == LiveRecordBuilders.DNS_MONITOR }) {
            telemetry.forEach(scan.id, LiveRecordBuilders.DNS_MONITOR) { r ->
                val reason = r.fields?.get("reason") as? String
                if (reason != null && (reason.startsWith("IOC:") || reason.startsWith("IOC_detect:"))) reasons += reason
            }
        }
        // An imported event cannot postdate its import: later times are bogus and never the reference.
        val latestImported = if (scan.source == TelemetrySource.LIVE_SCAN) {
            null
        } else {
            telemetry.latestEventTime(scan.id, notAfter = scan.timestamp)?.takeIf { it <= scan.timestamp }
        }
        val verdicts = campaignVerdicts(
            scan, findings.campaigns, campaignReferenceTime(scan, latestImported),
            findings.ruleCategoryById, findings.ruleScopes,
        )
        return FindingsContext(
            appCount = appCountText(scan, appRecords), displayNames = displayNames,
            dnsIocRows = dnsIocRows(scan, reasons),
            verdicts = verdicts, referenceFromLog = latestImported != null,
        )
    }

    /**
     * This scan's own stored app count. Only a fully stored scan's count is the number scanned:
     * under PARTIAL_RETENTION or a partway FAILED the surviving records would understate it.
     */
    private fun appCountText(scan: ScanResult, appRecords: ServiceSummary?): String = when {
        appRecords == null -> "N/A"
        scan.telemetryState == TelemetryState.PARTIAL_RETENTION || scan.telemetryState == TelemetryState.FAILED ->
            "N/A (only part of this scan's telemetry is stored)"
        else -> appRecords.records.toString()
    }

    @Suppress("LongMethod", "CyclomaticComplexMethod")
    private fun ReportOut.appendFindingsSections(scan: ScanResult, ctx: FindingsContext) {
        val scanSource = scan.source
        val displayNames = ctx.displayNames
        val campaignVerdicts = ctx.verdicts
        val referenceFromLog = ctx.referenceFromLog
        // -- Verdict + Summary + Action Guidance ----------------------------------
        appendVerdict(scan, ctx.appCount, ctx.dnsIocRows, campaignVerdicts)

        // -- Warning signs that add up -------------------------------------------
        // First, because a chain of events is the strongest evidence in the report.
        appendActivityChains(scan)

        // -- Device checks --------------------------------------------------------
        val allDeviceFlags = scan.deviceFlags
        if (allDeviceFlags.isNotEmpty()) {
            section("DEVICE CHECKS")
            val triggered = allDeviceFlags.filter { it.triggered }
            val passed    = allDeviceFlags.filter { !it.triggered }
            appendLine("  ${triggered.size} of ${allDeviceFlags.size} checks triggered")
            appendLine()

            if (triggered.isNotEmpty()) {
                appendLine("  Issues found:")
                triggered.sortedByDescending { severityOrdinal(it.level) }.forEach { finding ->
                    appendFinding(finding)
                }
            }
            if (passed.isNotEmpty()) {
                appendLine("  Checks passed:")
                passed.forEach { finding -> appendFinding(finding) }
            }
        } else {
            section("DEVICE CHECKS")
            appendLine("  (Bug report analysis -- device checks require a live scan)")
        }

        // -- Campaign check -------------------------------------------------------
        // One row per campaign (registry + rule-tag keys), from campaignVerdicts -- the
        // same list the summary's campaign lines render from, so the two never disagree.
        if (campaignVerdicts.isNotEmpty()) {
            section("MERCENARY SPYWARE CHECK")
            appendCampaignRows(campaignVerdicts, scan, referenceFromLog)
        }

        val dnsIocRows = ctx.dnsIocRows
        // Always its own heading: generic-feed hits (HaGeZi, ThreatFox) must never read as
        // rows of the mercenary check above (R7).
        if (dnsIocRows.isNotEmpty()) section("DNS IOC MATCHES")
        appendDnsIocMatches(dnsIocRows)

        // -- App risks ------------------------------------------------------------
        section("APP RISKS")
        val appRisks = scan.appRisks.filter { it.triggered && it.level.lowercase() != "informational" }
        if (appRisks.isEmpty()) {
            appendLine("  No high-risk applications detected.")
        } else {
            // Group findings by package name for a clean per-app display
            val byPackage = appRisks.groupBy {
                // A DNS-rule finding's app key is source_package: the app that made the query.
                it.matchContext["package_name"]?.toString()
                    ?: it.matchContext["source_package"]?.toString()
                    ?: "unknown"
            }
            appendLine("  ${byPackage.size} application(s) flagged")
            appendLine("  ${scan.knownMalwareCount} known malware / ${scan.riskySideloadCount} risky sideloads")
            appendLine()
            byPackage.entries
                .sortedByDescending { (_, findings) -> findings.maxOf { severityOrdinal(it.level) } }
                .forEach { (pkg, findings) ->
                    appendGroupedAppFindings(pkg, findings, displayNames, scanSource)
                }
        }

        // -- Bug-report findings --------------------------------------------------
        if (scan.bugReportFindings.isNotEmpty()) {
            section("BUG REPORT FINDINGS")
            scan.bugReportFindings.forEach { finding -> appendLine("  * $finding") }
        }
    }

    // -- Private helpers ----------------------------------------------------------

    /**
     * Checks that produced no verdict, and why.
     *
     * A rule the build could not evaluate, a path the device refused (#366), a chain
     * whose legs had no events (#370): each is accepted under-detection, and each used
     * to be invisible. A report that omits them reads exactly like one where everything
     * was checked and found clean. Grouped by [NotEvaluatedReason] in enum order so the
     * output is stable whatever order the scanners recorded them in.
     */
    private fun ReportOut.appendNotChecked(scan: ScanResult) {
        val byReason = scan.scannerErrors
            .mapNotNull { failure -> NotEvaluatedReason.fromSentinel(failure.exception)?.to(failure) }
            .groupBy({ it.first }, { it.second })
        if (byReason.isEmpty()) return
        appendLine()
        // The file's "--" convention rather than an em dash (see appendVerdict's "Flagged:" line).
        appendLine("$NOT_CHECKED_SECTION:")
        NotEvaluatedReason.entries.forEach { reason ->
            val failures = byReason[reason].orEmpty()
            if (failures.isNotEmpty()) {
                appendLine("  ${reason.heading}:")
                failures.forEach { failure ->
                    val needs = failure.missingEvidence
                        .joinToString(" and ") { evidenceName(it) }
                        .ifEmpty { "" }
                    val tail = if (needs.isEmpty()) "" else ": needs $needs, none recorded in this scan"
                    appendLine("    - ${failure.message}$tail")
                }
            }
        }
    }

    @Suppress("CyclomaticComplexMethod") // Verdict assembles summary, device posture, campaign,
    // and action guidance in a structured block -- splitting would fragment the output logic.
    private fun ReportOut.appendVerdict(
        scan: ScanResult,
        appCount: String,
        dnsIocRows: List<String>,
        campaignVerdicts: List<CampaignVerdict>,
    ) {
        val appRiskCount = scan.appRisks.count {
            it.triggered && it.level.lowercase() != "informational"
        }
        val deviceIssueCount = scan.deviceFlags.count { it.triggered }

        // One-liner verdict
        val verdict = when {
            appRiskCount == 0 && deviceIssueCount == 0 ->
                "No threats detected. Your phone appears secure."
            appRiskCount == 0 && deviceIssueCount > 0 ->
                "No suspicious apps found. $deviceIssueCount device setting(s) need attention."
            else ->
                "$appRiskCount app issue(s) and $deviceIssueCount device setting(s) found."
        }
        appendLine("  $verdict")
        // The line every reader reads must not stand alone when some checks never
        // ran: "your phone appears secure" is exactly the sentence an omission
        // turns into a false reassurance (#366, #370).
        if (scan.hasUnevaluatedRules) {
            appendLine("  Some checks did not run on this scan -- see $NOT_CHECKED_SECTION below.")
        }
        appendLine()

        // Summary block
        appendLine("  SUMMARY:")
        // This scan's own stored app records: an import (or a scan without them) has none.
        appendLine("    Apps scanned: $appCount -- Flagged: $appRiskCount")
        if (scan.knownMalwareCount > 0) {
            appendLine("    Known malware: ${scan.knownMalwareCount}")
        }
        if (scan.riskySideloadCount > 0) {
            appendLine("    Risky sideloads: ${scan.riskySideloadCount}")
        }

        // Device posture issues (all severity levels — these are conditions, not incidents)
        val triggeredDeviceFlags = scan.deviceFlags.filter { it.triggered }
        val chains = scan.activityChains.filter { it.triggered }
        if (chains.isNotEmpty()) {
            val labels = chains.map { it.title }.distinct().joinToString(", ")
            appendLine("    Warning signs that add up: ${chains.size} ($labels)")
        }
        if (triggeredDeviceFlags.isNotEmpty()) {
            val titles = triggeredDeviceFlags.take(3).map { it.title }
            val suffix = if (triggeredDeviceFlags.size > 3) ", ..." else ""
            appendLine("    Device posture: ${titles.joinToString(", ")}$suffix")
        }

        // Campaign detections (DETECTED only) and exposure (EXPOSED), from campaignVerdicts
        appendCampaignSummary(campaignVerdicts)

        // DNS IOC
        val dnsIocCount = dnsIocRows.size
        appendLine("    DNS IOC matches: $dnsIocCount")
        appendLine()

        // Action guidance (only if something actionable)
        appendActionGuidance(scan)
    }

    // Collects action guidance from Finding.guidance (rule-driven) and device posture summary.
    // Ordered: CRITICAL-prefixed first, then others, then device posture.
    private fun ReportOut.appendActionGuidance(scan: ScanResult) {
        val actions = mutableListOf<String>()

        // Collect rule-driven guidance from triggered app risk findings
        val appGuidance = scan.appRisks
            .filter { it.triggered && it.guidance.isNotEmpty() }
            .map { it.guidance }
            .distinct()
        // Sort so CRITICAL-prefixed items come first
        appGuidance.sortedByDescending { guidancePriority(it) }.forEach { actions.add(it) }

        // Chains of events: one line each, naming the app so the reader knows where to look.
        scan.activityChains.filter { it.triggered }.forEach { chain ->
            val pkg = chain.matchContext["package_name"]?.takeIf { it.isNotEmpty() } ?: "this device"
            actions.add("WARNING SIGNS: ${chain.title} ($pkg) -- review what this app has been doing recently")
        }
        // Device posture issues (summarized, not per-rule)
        val deviceIssues = scan.deviceFlags.filter { it.triggered }
        if (deviceIssues.isNotEmpty()) {
            val titles = deviceIssues.take(3).map { it.title }
            val suffix = if (deviceIssues.size > 3) ", ..." else ""
            actions.add("DEVICE: ${titles.joinToString(", ")}$suffix")
        }

        if (actions.isNotEmpty()) {
            appendLine("  ACTION REQUIRED:")
            actions.forEach { appendLine("    $it") }
            appendLine()
        }
    }

    // A chain of events -- several things that look minor on their own but add up.
    // Rendered first, and never again under APP RISKS or DEVICE CHECKS.
    private fun ReportOut.appendActivityChains(scan: ScanResult) {
        section(WARNING_SIGNS_SECTION)
        val chains = scan.activityChains.filter { it.triggered }
        // A pattern with no events to bind to was not checked at all; saying only
        // "none detected" would make silence sound like a result (#370).
        val unchecked = scan.scannerErrors.count {
            it.exception == NotEvaluatedReason.NO_EVENTS_TO_CHECK.sentinel
        }
        if (chains.isEmpty()) {
            appendLine("  No warning signs that add up were detected.")
            if (unchecked > 0) {
                appendLine(
                    "  $unchecked pattern(s) could not be checked on this scan -- " +
                        "see $NOT_CHECKED_SECTION."
                )
            }
            return
        }
        appendLine(
            "  ${chains.size} pattern(s) found -- separate events that look minor alone " +
                "but mean something together"
        )
        appendLine()
        if (unchecked > 0) {
            appendLine(
                "  $unchecked further pattern(s) could not be checked on this scan -- " +
                    "see $NOT_CHECKED_SECTION."
            )
            appendLine()
        }
        chains.sortedByDescending { severityOrdinal(it.level) }.forEach { chain ->
            appendFinding(chain)
            val pkg = chain.matchContext["package_name"].orEmpty()
            val members = chain.matchContext["member_event_ids"].orEmpty()
                .split(',').count { it.isNotBlank() }
            val where = if (pkg.isNotEmpty()) "App: $pkg" else "Device-wide"
            appendLine("           $where -- $members linked event(s); open the Timeline to see them")
        }
    }

    private fun ReportOut.appendFinding(finding: Finding) {
        val icon = if (finding.triggered) "[!!]" else "[OK]"
        val sev = finding.level.uppercase().padEnd(8)
        val mitre = finding.tags.filter { it.startsWith("attack.t") }
            .joinToString(", ") { it.removePrefix("attack.").uppercase() }
        val mitreSuffix = if (mitre.isNotEmpty() && finding.triggered) "  ($mitre)" else ""
        appendLine("  $icon  $sev  ${finding.title}$mitreSuffix")
        if (finding.triggered && finding.description.isNotEmpty()) {
            appendLine("           ${finding.description}")
        }
        if (finding.triggered && finding.remediation.isNotEmpty()) {
            finding.remediation.forEach { step ->
                appendLine("           -> $step")
            }
        }
    }

    private fun ReportOut.appendGroupedAppFindings(
        pkg: String,
        findings: List<Finding>,
        displayNames: Map<String, String>,
        scanSource: TelemetrySource,
    ) {
        val highest = findings.maxByOrNull { severityOrdinal(it.level) } ?: return
        val risk = highest.level.uppercase().padEnd(8)
        val appName = highest.matchContext["app_name"]?.toString()?.takeIf { it.isNotEmpty() }
            ?: displayNames[pkg]
            ?: pkg
        val subjectFlags = findings.flatMap { it.impliesFlags }.toSet()
        val isKnownMalware = "known_malware" in subjectFlags
        val isSideloaded = "sideloaded" in subjectFlags

        val flags = buildList {
            if (isKnownMalware) add("[!] Known Malware")
            if (isSideloaded) add("Sideloaded")
        }

        appendLine("  *  $risk  $appName")
        appendLine("     Package : $pkg")
        if (flags.isNotEmpty()) {
            appendLine("     Flags   : ${flags.joinToString(" / ")}")
        }
        val apkHash = highest.matchContext["apk_hash"]?.toString()
        if (!apkHash.isNullOrEmpty()) {
            appendLine("     APK SHA-256 : $apkHash")
        }
        val certHashVal = highest.matchContext["cert_hash"]?.toString()
        if (!certHashVal.isNullOrEmpty()) {
            appendLine("     Cert SHA-256: $certHashVal")
        }
        val reasons = findings.map { it.title }.distinct()
        appendLine("     Reasons : ${reasons.joinToString("; ")}")
        findings.mapNotNull { it.evidence as? Evidence.IocMatch }.filter { it.family.isNotBlank() }
            .distinctBy { it.matchedIndicator }.forEach { appendLine("     Matched : ${iocMatchLabel(it)}") }
        if (scanSource == TelemetrySource.LIVE_SCAN) { // imports: AndroDR was never in the path
            // Only IOC-lookup domain findings: other DNS rules (e.g. androdr-070 DDNS) also carry
            // is_blocked in matchContext but say nothing about threat-list blocking. Keyed on the
            // evidence, not a rule id, so a future rules-repo IOC domain rule gets the line too.
            findings.filter {
                (it.evidence as? Evidence.IocMatch)?.iocType == "domain" && it.matchContext.containsKey("domain")
            }.distinctBy { it.matchContext["domain"] }.forEach { f ->
                val state = blockedText(f.matchContext["reason"]) ?: return@forEach
                appendLine("     Blocked : ${f.matchContext["domain"]} $state")
            }
        }
        val mitreTechniques = findings.flatMap { it.tags }
            .filter { it.startsWith("attack.t") }
            .map { it.removePrefix("attack.").uppercase() }
            .distinct()
        if (mitreTechniques.isNotEmpty()) {
            appendLine("     MITRE   : ${mitreTechniques.joinToString(", ")}")
        }
        val allRemediation = findings.flatMap { it.remediation }.distinct()
        if (allRemediation.isNotEmpty()) {
            appendLine("     Action  : ${allRemediation.first()}")
        }

        // Per-app guidance from rules
        val guidance = findings.firstOrNull { it.guidance.isNotEmpty() }?.guidance
        if (guidance != null) {
            appendLine("     Guidance: $guidance")
        }
        appendLine()
    }

    private fun guidancePriority(guidance: String): Int =
        GuidanceUtils.guidancePriority(guidance)

    private fun severityOrdinal(level: String): Int = when (level.lowercase()) {
        "critical" -> 3
        "high" -> 2
        "medium" -> 1
        else -> 0
    }

    /**
     * What people see correlation findings called. Deliberately not "correlation" --
     * that is the internal category (FindingCategory.CORRELATION) -- and not "chain",
     * the engineering term. "Warning signs that add up" tells the reader why the
     * section exists: events that look minor on their own mean something together.
     * One place to change.
     */
    const val WARNING_SIGNS_SECTION = "WARNING SIGNS THAT ADD UP"

    /** Heading for the checks that produced no verdict (#366, #370). */
    const val NOT_CHECKED_SECTION = "WHAT THIS SCAN COULD NOT CHECK"

    /** Under a live scan's dns_monitor section: what a null reason means. */
    const val DNS_LIVE_NOTE = "  reason: null means the tunnel had no match when the domain was queried; " +
        "matches found at scan time are in FINDINGS."

    /** Heading of each per-service section of the scan's own stored records. */
    const val STORED_TELEMETRY_SECTION = "STORED TELEMETRY"

    /** The state line for a scan whose records retention partly removed (followed by the count left). */
    const val TELEMETRY_PARTIAL =
        "Stored telemetry: PARTIAL_RETENTION -- retention removed some of this scan's records;"

    /** The state line for a scan saved before telemetry was stored. */
    const val TELEMETRY_NONE =
        "Stored telemetry: NONE -- this scan was saved before telemetry was stored; only its findings remain."

    /** The state line for a scan whose storage failed before any record was stored. */
    const val TELEMETRY_FAILED =
        "Stored telemetry: FAILED -- storage failed during this scan; it was checked without saving its telemetry."

    /**
     * The state line for a scan whose storage failed partway (followed by the count stored): the
     * records written before the disk filled stay, and are printed below it.
     */
    const val TELEMETRY_FAILED_PARTWAY = "Stored telemetry: FAILED -- storage failed partway;"

    private const val RULE = "============================================================"
}
