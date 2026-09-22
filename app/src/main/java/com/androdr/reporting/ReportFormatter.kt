package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.DeviceTelemetry
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ProcessTelemetry
import com.androdr.data.model.ReceiverTelemetry
import com.androdr.data.model.ScanResult
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.Finding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Produces human-readable plaintext security reports from scan data.
 * All methods are pure (no I/O) so they can be unit-tested without a device.
 * Output is strictly ASCII -- no Unicode characters.
 */
object ReportFormatter {

    @Suppress("LongMethod", "CyclomaticComplexMethod", "LongParameterList") // Report formatting
    // requires assembling all sections in a specific order; the branching reflects the conditional
    // severity/status display logic per section. All telemetry types needed for complete rendering.
    fun formatScanReport(
        scan: ScanResult,
        dnsEvents: List<DnsEvent>,
        logLines: List<String>,
        appInventory: List<AppTelemetry> = emptyList(),
        displayNames: Map<String, String> = emptyMap(),
        mode: ExportMode = ExportMode.BOTH,
        deviceTelemetry: List<DeviceTelemetry> = emptyList(),
        processTelemetry: List<ProcessTelemetry> = emptyList(),
        fileTelemetry: List<FileArtifactTelemetry> = emptyList(),
        accessibilityTelemetry: List<AccessibilityTelemetry> = emptyList(),
        receiverTelemetry: List<ReceiverTelemetry> = emptyList(),
        appOpsTelemetry: List<AppOpsTelemetry> = emptyList(),
        intrusionEvents: List<ForensicTimelineEvent> = emptyList(),
        versionName: String,
    ): String = buildString {
        val includeFindings = mode != ExportMode.TELEMETRY_ONLY
        val includeTelemetry = mode != ExportMode.FINDINGS_ONLY
        val timestampFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        val generated = timestampFmt.format(Date())
        val scanDate = timestampFmt.format(Date(scan.timestamp))

        // -- Header ---------------------------------------------------------------
        appendLine(RULE)
        appendLine("  AndroDR Security Report")
        appendLine("  Format    : v${ReportExporter.EXPORT_FORMAT_VERSION} (mode=${mode.name})")
        appendLine("  Version   : $versionName")
        appendLine("  Generated : $generated")
        appendLine("  Scan time : $scanDate")
        appendLine("  Android   : ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("  Device    : ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("  Patch     : ${Build.VERSION.SECURITY_PATCH}")
        appendLine(RULE)
        appendLine()
        // One overall-risk calculation, shared with every UI surface (dashboard,
        // history). This header used to run a second ladder that scored the first word
        // of each rule's prose `display.guidance` instead of its severity. Guidance is
        // advice text, not a validated enum, so the two drifted apart as the corpus
        // grew and the header was wrong in both directions (#332): one medium
        // "REVIEW --" finding printed HIGH, while critical rules whose guidance is
        // ordinary prose (androdr-094) or absent (androdr-089) printed LOW.
        // Device posture still caps at MEDIUM -- that rule lives in overallRiskLevel,
        // which is where #70 intended it. Pinned by OverallRiskConsistencyTest.
        val reportedRisk = scan.overallRiskLevel.name
        if (includeFindings) {
            appendLine("  OVERALL RISK: $reportedRisk")
            appendLine()
            section("FINDINGS SECTION")
            appendFindingsSections(scan, dnsEvents, appInventory, displayNames)

            // Intentionally inside the includeFindings branch: a capability skip is a
            // caveat ON the findings ("this list is missing these rules"), so it rides
            // the same flag — a telemetry-only export has no findings list to caveat.
            appendNotChecked(scan)
        }

        if (includeTelemetry) {
            section("TELEMETRY SECTION")
            appendTelemetrySections(
                dnsEvents, logLines, appInventory, displayNames,
                deviceTelemetry, processTelemetry, fileTelemetry,
                accessibilityTelemetry, receiverTelemetry, appOpsTelemetry,
                intrusionEvents, scan.source
            )
        }

        // -- Footer ---------------------------------------------------------------
        appendLine()
        appendLine(RULE)
        appendLine("  End of report / AndroDR / scan id ${scan.id}")
        appendLine(RULE)
    }

    // Legacy inline body replaced by section helpers below. Original code is
    // retained as private helpers so BOTH mode output is byte-identical to
    // the pre-refactor report (minus the section header markers).
    @Suppress("LongMethod", "CyclomaticComplexMethod")
    private fun StringBuilder.appendFindingsSections(
        scan: ScanResult,
        dnsEvents: List<DnsEvent>,
        appInventory: List<AppTelemetry>,
        displayNames: Map<String, String>
    ) {
        // -- Verdict + Summary + Action Guidance ----------------------------------
        appendVerdict(scan, dnsEvents, appInventory)

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
        val campaignFindings = scan.deviceFlags.filter { f ->
            f.tags.any { it.startsWith("campaign.") }
        }
        if (campaignFindings.isNotEmpty()) {
            section("MERCENARY SPYWARE CHECK")
            val clear = campaignFindings.filter { !it.triggered }
            val detected = campaignFindings.filter { it.triggered }

            clear.forEach { finding ->
                appendLine("  [OK]  ${campaignLabel(finding)}: not detected")
            }
            detected.forEach { finding ->
                appendLine("  [!!]  ${campaignLabel(finding)}: DETECTED -- ${finding.title}")
            }

            // DNS-based campaign hits from IOC domain matches
            val dnsCampaigns = dnsEvents
                .mapNotNull { it.reason }
                .filter { it.startsWith("IOC:") || it.startsWith("IOC_detect:") }
                .map { it.removePrefix("IOC:").removePrefix("IOC_detect:").trim() }
                .filter { it.isNotEmpty() }
                .distinct()
            if (dnsCampaigns.isNotEmpty()) {
                appendLine()
                appendLine("  DNS IOC matches linked to:")
                dnsCampaigns.forEach { campaign ->
                    appendLine("  [!!]  $campaign (domain indicator)")
                }
            }
            appendLine()
        }

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
                    appendGroupedAppFindings(pkg, findings, displayNames)
                }
        }

        // -- Bug-report findings --------------------------------------------------
        if (scan.bugReportFindings.isNotEmpty()) {
            section("BUG REPORT FINDINGS")
            scan.bugReportFindings.forEach { finding -> appendLine("  * $finding") }
        }
    }

    @Suppress("LongParameterList")
    private fun StringBuilder.appendTelemetrySections(
        dnsEvents: List<DnsEvent>,
        logLines: List<String>,
        appInventory: List<AppTelemetry>,
        displayNames: Map<String, String>,
        deviceTelemetry: List<DeviceTelemetry> = emptyList(),
        processTelemetry: List<ProcessTelemetry> = emptyList(),
        fileTelemetry: List<FileArtifactTelemetry> = emptyList(),
        accessibilityTelemetry: List<AccessibilityTelemetry> = emptyList(),
        receiverTelemetry: List<ReceiverTelemetry> = emptyList(),
        appOpsTelemetry: List<AppOpsTelemetry> = emptyList(),
        intrusionEvents: List<ForensicTimelineEvent> = emptyList(),
        scanSource: TelemetrySource = TelemetrySource.LIVE_SCAN,
    ) {
        val dnsFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

        // -- DNS activity ---------------------------------------------------------
        // Whose DNS? The live tunnel's log belongs to the scan that captured it. An
        // imported file's report shows the import's own queries or none at all --
        // never the phone's unrelated tunnel history under an import's header (#375).
        section("DNS ACTIVITY")
        if (scanSource == TelemetrySource.LIVE_SCAN) {
            appendLiveDns(dnsEvents, displayNames, dnsFmt)
        } else {
            appendImportedDns(intrusionEvents, displayNames, dnsFmt)
        }

        // -- Intrusion log (imported, #342) --------------------------------------
        if (intrusionEvents.isNotEmpty()) {
            section("INTRUSION LOG (imported, ${intrusionEvents.size} events)")
            val fullFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
            intrusionEvents.take(500).forEach { ev ->
                val time = fullFmt.format(Date(ev.startTimestamp))
                val app = ev.packageName.ifEmpty { "unknown" }
                appendLine("  $time  ${ev.description.padEnd(50)}  <- $app")
            }
        }

        // -- App hash inventory ---------------------------------------------------
        if (appInventory.isNotEmpty()) {
            val appsWithHashes = appInventory.filter { !it.apkHash.isNullOrEmpty() }
            if (appsWithHashes.isNotEmpty()) {
                section("APP HASH INVENTORY (${appsWithHashes.size} apps)")
                appsWithHashes.sortedBy { it.packageName }.forEach { app ->
                    val name = app.appName.ifEmpty {
                        displayNames[app.packageName] ?: app.packageName
                    }
                    appendLine("  $name")
                    appendLine("     Package    : ${app.packageName}")
                    appendLine("     APK SHA-256: ${app.apkHash}")
                    if (!app.certHash.isNullOrEmpty()) {
                        appendLine("     Cert SHA-256: ${app.certHash}")
                    }
                    appendLine()
                }
            }
        }

        // -- Extended telemetry sections -----------------------------------------
        appendExtendedTelemetry(
            deviceTelemetry, processTelemetry, fileTelemetry,
            accessibilityTelemetry, receiverTelemetry, appOpsTelemetry
        )

        // -- App log --------------------------------------------------------------
        section("APPLICATION LOG  (${logLines.size} lines)")
        if (logLines.isEmpty()) {
            appendLine("  (no log lines captured)")
        } else {
            logLines.forEach { line -> appendLine("  $line") }
        }
    }

    @Suppress("LongMethod", "LongParameterList") // Renders 6 telemetry sub-sections sequentially;
    // splitting further would scatter related rendering logic across many tiny methods.
    private fun StringBuilder.appendExtendedTelemetry(
        deviceTelemetry: List<DeviceTelemetry>,
        processTelemetry: List<ProcessTelemetry>,
        fileTelemetry: List<FileArtifactTelemetry>,
        accessibilityTelemetry: List<AccessibilityTelemetry>,
        receiverTelemetry: List<ReceiverTelemetry>,
        appOpsTelemetry: List<AppOpsTelemetry>,
    ) {
        // -- Device posture telemetry ---------------------------------------------
        if (deviceTelemetry.isNotEmpty()) {
            section("DEVICE POSTURE TELEMETRY")
            deviceTelemetry.forEach { d ->
                appendLine("  ADB Enabled       : ${d.adbEnabled}")
                appendLine("  Dev Options        : ${d.devOptionsEnabled}")
                appendLine("  Unknown Sources    : ${d.unknownSourcesEnabled}")
                appendLine("  Screen Lock        : ${d.screenLockEnabled}")
                appendLine("  Patch Level        : ${d.patchLevel.ifEmpty { "unknown" }}")
                appendLine("  Patch Age (days)   : ${d.patchAgeDays}")
                appendLine("  Bootloader Unlocked: ${d.bootloaderUnlocked}")
                appendLine("  WiFi ADB           : ${d.wifiAdbEnabled}")
                appendLine("  Unpatched CVEs     : ${d.unpatchedCveCount}")
                appendLine()
            }
        }

        // -- Accessibility services ----------------------------------------------
        if (accessibilityTelemetry.isNotEmpty()) {
            section("ACCESSIBILITY SERVICES (${accessibilityTelemetry.size})")
            accessibilityTelemetry.forEach { a ->
                val sysFlag = if (a.isSystemApp) "system" else "non-system"
                appendLine("  ${a.packageName} / ${a.serviceName} ($sysFlag)")
            }
            appendLine()
        }

        // -- Broadcast receivers -------------------------------------------------
        if (receiverTelemetry.isNotEmpty()) {
            section("BROADCAST RECEIVERS (${receiverTelemetry.size})")
            receiverTelemetry.forEach { r ->
                appendLine("  ${r.packageName} / ${r.intentAction} (system: ${r.isSystemApp})")
            }
            appendLine()
        }

        // -- App operations ------------------------------------------------------
        if (appOpsTelemetry.isNotEmpty()) {
            val timeFmt = SimpleDateFormat("HH:mm", Locale.US)
            section("APP OPERATIONS (${appOpsTelemetry.size})")
            appOpsTelemetry.forEach { op ->
                val lastAccess = if (op.lastAccessTime > 0)
                    timeFmt.format(Date(op.lastAccessTime)) else "never"
                appendLine("  ${op.packageName} / ${op.operation} / last access: $lastAccess")
            }
            appendLine()
        }

        // -- Running processes ---------------------------------------------------
        if (processTelemetry.isNotEmpty()) {
            section("RUNNING PROCESSES (${processTelemetry.size})")
            processTelemetry.forEach { p ->
                val state = if (p.isForeground) "foreground" else "background"
                val pkg = p.packageName ?: p.processName
                appendLine("  $pkg ($state)")
            }
            appendLine()
        }

        // -- File artifact checks ------------------------------------------------
        if (fileTelemetry.isNotEmpty()) {
            val checked = fileTelemetry.filter { it.accessible }
            val skipped = fileTelemetry.filter { !it.accessible }
            section("FILE ARTIFACT CHECKS")
            if (checked.isNotEmpty()) {
                checked.forEach { f ->
                    val status = if (f.fileExists) {
                        "FOUND (${f.fileSize ?: 0} bytes) — investigate immediately"
                    } else {
                        "clear"
                    }
                    appendLine("  ${f.filePath} : $status")
                }
            }
            if (skipped.isNotEmpty()) {
                appendLine()
                appendLine("  ${skipped.size} path(s) could not be checked (requires root/ADB access):")
                skipped.forEach { f ->
                    appendLine("    ${f.filePath}")
                }
                appendLine("  For a complete check: adb shell ls -la <path>")
            }
            appendLine()
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
    private fun StringBuilder.appendNotChecked(scan: ScanResult) {
        val byReason = scan.scannerErrors
            .mapNotNull { failure -> NotEvaluatedReason.fromSentinel(failure.exception)?.to(failure) }
            .groupBy({ it.first }, { it.second })
        if (byReason.isEmpty()) return
        appendLine()
        // ASCII-only per class doc: em dash replaced with the file's existing
        // "--" convention (see e.g. appendVerdict's "Flagged:" line).
        appendLine("$NOT_CHECKED_SECTION:")
        NotEvaluatedReason.entries.forEach { reason ->
            val failures = byReason[reason].orEmpty()
            if (failures.isNotEmpty()) {
                appendLine("  ${reason.heading}:")
                failures.forEach { appendLine("    - ${it.message}") }
            }
        }
    }

    private fun StringBuilder.section(title: String) {
        appendLine(THIN)
        appendLine("  $title")
        appendLine(THIN)
    }

    @Suppress("CyclomaticComplexMethod") // Verdict assembles summary, device posture, campaign,
    // and action guidance in a structured block -- splitting would fragment the output logic.
    private fun StringBuilder.appendVerdict(
        scan: ScanResult,
        dnsEvents: List<DnsEvent>,
        appInventory: List<AppTelemetry>
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
        appendLine()

        // Summary block
        appendLine("  SUMMARY:")
        val totalApps = if (appInventory.isNotEmpty()) appInventory.size.toString() else "N/A"
        appendLine("    Apps scanned: $totalApps -- Flagged: $appRiskCount")
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

        // Campaign detections
        val campaigns = scan.deviceFlags
            .filter { f -> f.triggered && f.tags.any { it.startsWith("campaign.") } }
        if (campaigns.isNotEmpty()) {
            val labels = campaigns.map { campaignLabel(it) }.distinct()
            appendLine("    Campaign detections: ${labels.joinToString(", ")}")
        }

        // DNS IOC
        val dnsIocCount = dnsEvents.count { it.reason != null }
        appendLine("    DNS IOC matches: $dnsIocCount")
        appendLine()

        // Action guidance (only if something actionable)
        appendActionGuidance(scan)
    }

    // Collects action guidance from Finding.guidance (rule-driven) and device posture summary.
    // Ordered: CRITICAL-prefixed first, then others, then device posture.
    private fun StringBuilder.appendActionGuidance(scan: ScanResult) {
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
    private fun StringBuilder.appendActivityChains(scan: ScanResult) {
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

    private fun StringBuilder.appendFinding(finding: Finding) {
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

    private fun StringBuilder.appendGroupedAppFindings(
        pkg: String,
        findings: List<Finding>,
        displayNames: Map<String, String>
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

    private fun campaignLabel(finding: Finding): String =
        finding.tags.filter { it.startsWith("campaign.") }
            .joinToString(" / ") { tag ->
                tag.removePrefix("campaign.").replaceFirstChar { c -> c.uppercase() }
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


    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"
}
