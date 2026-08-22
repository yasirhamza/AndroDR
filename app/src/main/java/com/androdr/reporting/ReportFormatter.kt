package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.DeviceTelemetry
import com.androdr.cellular.CellularRedaction
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ProcessTelemetry
import com.androdr.data.model.ReceiverTelemetry
import com.androdr.data.model.ScanResult
import com.androdr.data.model.UNREGISTERED_IOC_LOOKUP
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
        cellularEvents: List<ForensicTimelineEvent> = emptyList(),
        cellularSnapshot: CellularSnapshot? = null,
        cellularDeliveries: Int = 0,
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
        // Overall risk driven by app threats with rule guidance. Device posture is a
        // condition (not an incident) so it caps at MEDIUM -- nothing has happened yet.
        val maxAppGuidancePriority = scan.appRisks
            .filter { it.triggered && it.guidance.isNotEmpty() }
            .maxOfOrNull { guidancePriority(it.guidance) } ?: 0
        val reportedRisk = when {
            maxAppGuidancePriority >= 3 -> "CRITICAL"
            maxAppGuidancePriority >= 1 -> "HIGH"
            scan.deviceFlags.any { it.triggered } -> "MEDIUM"
            else -> "LOW"
        }
        if (includeFindings) {
            appendLine("  OVERALL RISK: $reportedRisk")
            appendLine()
            section("FINDINGS SECTION")
            appendFindingsSections(scan, dnsEvents, appInventory, displayNames)
            appendCellularSection(cellularEvents)

            // Intentionally inside the includeFindings branch: a capability skip is a
            // caveat ON the findings ("this list is missing these rules"), so it rides
            // the same flag — a telemetry-only export has no findings list to caveat.
            val capabilitySkips = scan.scannerErrors.filter { it.exception == UNREGISTERED_IOC_LOOKUP }
            if (capabilitySkips.isNotEmpty()) {
                appendLine()
                // ASCII-only per class doc: em dash replaced with the file's existing
                // "--" convention (see e.g. appendVerdict's "Flagged:" line).
                appendLine("RULES NOT EVALUATED ON THIS BUILD (missing capability -- update the app):")
                capabilitySkips.forEach { appendLine("  - ${it.message}") }
            }
        }

        if (includeTelemetry) {
            section("TELEMETRY SECTION")
            appendTelemetrySections(
                dnsEvents, logLines, appInventory, displayNames,
                deviceTelemetry, processTelemetry, fileTelemetry,
                accessibilityTelemetry, receiverTelemetry, appOpsTelemetry
            )
            appendCellularTelemetry(cellularSnapshot, cellularDeliveries)
        }

        // -- Footer ---------------------------------------------------------------
        appendLine()
        appendLine(RULE)
        appendLine("  End of report / AndroDR / scan id ${scan.id}")
        appendLine(RULE)
    }

    /**
     * Radio state observed at export time.
     *
     * Recorded even when nothing fired, for two reasons. A report that shows
     * only anomalies cannot distinguish "the radio was clean" from "the
     * monitor was never running" — and on this feature that difference is
     * real, because cell info comes back EMPTY rather than erroring when the
     * caller is not permitted to read it. The delivery count is the evidence
     * the monitor was alive.
     *
     * Redacted like every other handoff path: condition, not tower identity.
     */
    private fun StringBuilder.appendCellularTelemetry(
        snapshot: CellularSnapshot?,
        deliveries: Int,
    ) {
        section("CELLULAR TELEMETRY (TIER 1)")
        if (snapshot == null) {
            appendLine("  No radio telemetry captured this session.")
            appendLine("  Either the monitor was not running, or no serving cell was observed.")
            appendLine()
            return
        }
        appendLine("  Radio updates observed this session: $deliveries")
        appendLine("  Serving cell at export time:")
        appendLine("    technology      : ${snapshot.rat}")
        appendLine("    bandwidth       : ${snapshot.bandwidthKhz?.let { "$it kHz" } ?: "not reported"}")
        appendLine("    channel (earfcn): ${snapshot.earfcn ?: "not reported"}")
        appendLine("    neighbour cells : ${snapshot.neighborCount}")
        appendLine("    serving RSRP    : ${snapshot.servingRsrp?.let { "$it dBm" } ?: "not reported"}")
        appendLine("    TAC changes (5m): ${snapshot.tacChangesLast5m}")
        appendLine("    TAC changed     : ${snapshot.tacChanged}")
        appendLine("    RAT changed     : ${snapshot.ratChanged}")
        appendLine("  ${CellularRedaction.REDACTION_NOTE}")
        appendLine()
    }

    /**
     * Tier 1 cellular findings.
     *
     * These come from the forensic timeline rather than [ScanResult.findings]:
     * the radio emitter is event-driven and continuous, so a finding is not
     * produced by any particular scan. Each row carries the full radio context
     * it fired on, because a cellular finding cannot be judged true or false
     * after the fact without the snapshot that produced it.
     */
    private fun StringBuilder.appendCellularSection(events: List<ForensicTimelineEvent>) {
        if (events.isEmpty()) return
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        section("CELLULAR (TIER 1)")
        appendLine("  ${events.size} finding(s) from radio telemetry.")
        appendLine()
        events.forEach { e ->
            appendLine("  [${fmt.format(Date(e.startTimestamp))}] ${e.description}")
            if (e.ruleId.isNotEmpty()) appendLine("    rule: ${e.ruleId}")
            if (e.attackTechniqueId.isNotEmpty()) {
                appendLine("    technique: ${e.attackTechniqueId}")
            }
            // Redacted: a report is a handoff artifact and must not carry a
            // tower-level location trail. Full context stays on-device.
            if (e.details.isNotEmpty()) {
                appendLine("    context: ${CellularRedaction.redact(e.details)}")
            }
            appendLine()
        }
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
                it.matchContext["package_name"]?.toString() ?: "unknown"
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
    ) {
        val dnsFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

        // -- DNS activity ---------------------------------------------------------
        section("DNS ACTIVITY")
        if (dnsEvents.isEmpty()) {
            appendLine("  No DNS events recorded.")
        } else {
            val matched = dnsEvents.count { it.reason != null }
            appendLine("  ${dnsEvents.size} events / $matched matched")
            appendLine()
            dnsEvents.take(500).forEach { event ->
                val time = dnsFmt.format(Date(event.timestamp))
                val state = if (event.reason != null) "[MATCHED]" else "[ALLOWED]"
                val app = event.appName
                    ?: if (event.appUid == -1) "unknown" else "uid:${event.appUid}"
                appendLine("  $state  $time  ${event.domain.padEnd(50)}  <- $app")
                if (event.reason != null) {
                    appendLine("           reason: ${event.reason}")
                }
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

    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"
}
