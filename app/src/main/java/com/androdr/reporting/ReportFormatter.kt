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

    private val timestampFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
    private val dnsFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    @Suppress("LongMethod", "CyclomaticComplexMethod") // Report formatting requires assembling all
    // sections (header, device flags, app risks, DNS events, logs) in a specific order; the
    // branching reflects the conditional severity/status display logic per section.
    fun formatScanReport(
        scan: ScanResult,
        dnsEvents: List<DnsEvent>,
        logLines: List<String>
    ): String = buildString {
        val generated = timestampFmt.format(Date())
        val scanDate = timestampFmt.format(Date(scan.timestamp))

        // -- Header ---------------------------------------------------------------
        appendLine(RULE)
        appendLine("  AndroDR Security Report")
        appendLine("  Generated : $generated")
        appendLine("  Scan time : $scanDate")
        appendLine("  Android   : ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("  Device    : ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("  Patch     : ${Build.VERSION.SECURITY_PATCH}")
        appendLine(RULE)
        appendLine()
        appendLine("  OVERALL RISK: ${scan.overallRiskLevel.name}")
        appendLine()

        // -- Device checks --------------------------------------------------------
        section("DEVICE CHECKS")
        val triggered = scan.deviceFlags.filter { it.triggered }
        val passed    = scan.deviceFlags.filter { !it.triggered }
        appendLine("  ${triggered.size} of ${scan.deviceFlags.size} checks triggered")
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

        // -- App risks ------------------------------------------------------------
        section("APP RISKS")
        val appRisks = scan.appRisks
        if (appRisks.isEmpty()) {
            appendLine("  No high-risk applications detected.")
        } else {
            val triggeredApps = appRisks.filter { it.triggered }
            appendLine("  ${triggeredApps.size} application finding(s) flagged")
            appendLine("  ${scan.knownMalwareCount} known malware \u00b7 ${scan.riskySideloadCount} risky sideloads")
            appendLine()
            triggeredApps.sortedByDescending { severityOrdinal(it.level) }.forEach { finding ->
                appendAppFinding(finding)
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

    private fun StringBuilder.appendAppFinding(finding: Finding) {
        val risk = finding.level.uppercase().padEnd(8)
        appendLine("  \u25cf  $risk  ${finding.matchContext["app_name"] ?: finding.title}")
        appendLine("     Package : ${finding.matchContext["package_name"] ?: "unknown"}")
        if (finding.remediation.isNotEmpty()) {
            appendLine("     Action  : ${finding.remediation.joinToString("; ")}")
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
