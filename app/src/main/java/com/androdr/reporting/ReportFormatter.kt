package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ScanResult
import com.androdr.sigma.Finding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Produces human-readable plaintext security reports from scan data.
 * All methods are pure (no I/O) so they can be unit-tested without a device.
 */
object ReportFormatter {

    @Suppress("LongMethod", "CyclomaticComplexMethod") // Report formatting requires assembling all
    // sections (header, device flags, app risks, DNS events, logs) in a specific order; the
    // branching reflects the conditional severity/status display logic per section.
    fun formatScanReport(
        scan: ScanResult,
        dnsEvents: List<DnsEvent>,
        logLines: List<String>
    ): String = buildString {
        val timestampFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        val dnsFmt = SimpleDateFormat("HH:mm:ss", Locale.US)
        val generated = timestampFmt.format(Date())
        val scanDate = timestampFmt.format(Date(scan.timestamp))

        // -- Header ---------------------------------------------------------------
        appendLine(RULE)
        appendLine("  AndroDR Security Report")
        appendLine("  Version   : ${com.androdr.BuildConfig.VERSION_NAME}")
        appendLine("  Generated : $generated")
        appendLine("  Scan time : $scanDate")
        appendLine("  Android   : ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("  Device    : ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("  Patch     : ${Build.VERSION.SECURITY_PATCH}")
        appendLine(RULE)
        appendLine()
        appendLine("  OVERALL RISK: ${scan.overallRiskLevel.name}")

        appendLine()
        val appRiskCount = scan.appRisks.count {
            it.triggered && it.level.lowercase() != "informational"
        }
        val deviceIssueCount = scan.deviceFlags.count { it.triggered }
        val verdict = when {
            appRiskCount == 0 && deviceIssueCount == 0 ->
                "No threats detected. Your phone appears secure."
            appRiskCount == 0 && deviceIssueCount > 0 ->
                "No suspicious apps found. $deviceIssueCount device setting(s) need attention."
            else ->
                "$appRiskCount app issue(s) and $deviceIssueCount device setting(s) found. " +
                    "Review the details below."
        }
        appendLine("  $verdict")
        appendLine()

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
            appendLine("  (Bug report analysis — device checks require a live scan)")
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
            appendLine("  ${scan.knownMalwareCount} known malware \u00b7 ${scan.riskySideloadCount} risky sideloads")
            appendLine()
            byPackage.entries
                .sortedByDescending { (_, findings) -> findings.maxOf { severityOrdinal(it.level) } }
                .forEach { (pkg, findings) ->
                    appendGroupedAppFindings(pkg, findings)
                }
        }

        // -- DNS activity ---------------------------------------------------------
        section("DNS ACTIVITY")
        if (dnsEvents.isEmpty()) {
            appendLine("  No DNS events recorded.")
        } else {
            val matched = dnsEvents.count { it.reason != null }
            appendLine("  ${dnsEvents.size} events \u00b7 $matched matched")
            appendLine()
            dnsEvents.take(500).forEach { event ->
                val time = dnsFmt.format(Date(event.timestamp))
                val state = if (event.reason != null) "[MATCHED]" else "[ALLOWED]"
                val app = event.appName
                    ?: if (event.appUid == -1) "unknown" else "uid:${event.appUid}"
                appendLine("  $state  $time  ${event.domain.padEnd(50)}  \u2190 $app")
                if (event.reason != null) {
                    appendLine("           reason: ${event.reason}")
                }
            }
        }

        // -- Bug-report findings --------------------------------------------------
        if (scan.bugReportFindings.isNotEmpty()) {
            section("BUG REPORT FINDINGS")
            scan.bugReportFindings.forEach { finding -> appendLine("  \u2022 $finding") }
        }

        // -- App log --------------------------------------------------------------
        section("APPLICATION LOG  (${logLines.size} lines)")
        if (logLines.isEmpty()) {
            appendLine("  (no log lines captured)")
        } else {
            logLines.forEach { line -> appendLine("  $line") }
        }

        // -- Footer ---------------------------------------------------------------
        appendLine()
        appendLine(RULE)
        appendLine("  End of report \u00b7 AndroDR \u00b7 scan id ${scan.id}")
        appendLine(RULE)
    }

    // -- Private helpers ----------------------------------------------------------

    private fun StringBuilder.section(title: String) {
        appendLine(THIN)
        appendLine("  $title")
        appendLine(THIN)
    }

    private fun StringBuilder.appendFinding(finding: Finding) {
        val icon = if (finding.triggered) "[\u2717]" else "[\u2713]"
        val sev = finding.level.uppercase().padEnd(8)
        appendLine("  $icon  $sev  ${finding.title}")
        if (finding.triggered && finding.description.isNotEmpty()) {
            appendLine("           ${finding.description}")
        }
    }

    private fun StringBuilder.appendGroupedAppFindings(pkg: String, findings: List<Finding>) {
        val highest = findings.maxByOrNull { severityOrdinal(it.level) } ?: return
        val risk = highest.level.uppercase().padEnd(8)
        val appName = highest.matchContext["app_name"]?.toString() ?: pkg
        val isKnownMalware = findings.any { it.ruleId.startsWith("androdr-00") }
        val isSideloaded = findings.any { it.ruleId == "androdr-010" }

        val flags = buildList {
            if (isKnownMalware) add("\u26a0 Known Malware")
            if (isSideloaded) add("Sideloaded")
        }

        appendLine("  \u25cf  $risk  $appName")
        appendLine("     Package : $pkg")
        if (flags.isNotEmpty()) {
            appendLine("     Flags   : ${flags.joinToString(" \u00b7 ")}")
        }
        val reasons = findings.map { it.title }.distinct()
        appendLine("     Reasons : ${reasons.joinToString("; ")}")
        val allRemediation = findings.flatMap { it.remediation }.distinct()
        if (allRemediation.isNotEmpty()) {
            appendLine("     Action  : ${allRemediation.first()}")
        }
        appendLine()
    }

    private fun severityOrdinal(level: String): Int = when (level.lowercase()) {
        "critical" -> 3
        "high" -> 2
        "medium" -> 1
        else -> 0
    }

    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"
}
