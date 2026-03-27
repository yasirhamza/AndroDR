package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.AppRisk
import com.androdr.data.model.DeviceFlag
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.Severity
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

        // ── Header ─────────────────────────────────────────────────────────────
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

        // ── Device checks ──────────────────────────────────────────────────────
        section("DEVICE CHECKS")
        val triggered = scan.deviceFlags.filter { it.isTriggered }
        val passed    = scan.deviceFlags.filter { !it.isTriggered }
        appendLine("  ${triggered.size} of ${scan.deviceFlags.size} checks triggered")
        appendLine()

        if (triggered.isNotEmpty()) {
            appendLine("  Issues found:")
            triggered.sortedByDescending { it.severity.ordinal }.forEach { flag ->
                appendDeviceFlag(flag, triggered = true)
            }
        }
        if (passed.isNotEmpty()) {
            appendLine("  Checks passed:")
            passed.forEach { flag -> appendDeviceFlag(flag, triggered = false) }
        }

        // ── App risks ──────────────────────────────────────────────────────────
        section("APP RISKS")
        if (scan.appRisks.isEmpty()) {
            appendLine("  No high-risk applications detected.")
        } else {
            appendLine("  ${scan.appRisks.size} application(s) flagged")
            appendLine("  ${scan.knownMalwareCount} known malware · ${scan.riskySideloadCount} risky sideloads")
            appendLine()
            scan.appRisks.sortedByDescending { it.riskLevel.score }.forEach { app ->
                appendAppRisk(app)
            }
        }

        // ── DNS activity ───────────────────────────────────────────────────────
        section("DNS ACTIVITY")
        if (dnsEvents.isEmpty()) {
            appendLine("  No DNS events recorded.")
        } else {
            val matched = dnsEvents.count { it.reason != null }
            appendLine("  ${dnsEvents.size} events · $matched matched")
            appendLine()
            dnsEvents.take(500).forEach { event ->
                val time = dnsFmt.format(Date(event.timestamp))
                val state = if (event.reason != null) "[MATCHED]" else "[ALLOWED]"
                val app = event.appName
                    ?: if (event.appUid == -1) "unknown" else "uid:${event.appUid}"
                appendLine("  $state  $time  ${event.domain.padEnd(50)}  ← $app")
                if (event.reason != null) {
                    appendLine("           reason: ${event.reason}")
                }
            }
        }

        // ── Bug-report findings ────────────────────────────────────────────────
        if (scan.bugReportFindings.isNotEmpty()) {
            section("BUG REPORT FINDINGS")
            scan.bugReportFindings.forEach { finding -> appendLine("  • $finding") }
        }

        // ── App log ────────────────────────────────────────────────────────────
        section("APPLICATION LOG  (${logLines.size} lines)")
        if (logLines.isEmpty()) {
            appendLine("  (no log lines captured)")
        } else {
            logLines.forEach { line -> appendLine("  $line") }
        }

        // ── Footer ─────────────────────────────────────────────────────────────
        appendLine()
        appendLine(RULE)
        appendLine("  End of report · AndroDR · scan id ${scan.id}")
        appendLine(RULE)
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private fun StringBuilder.section(title: String) {
        appendLine(THIN)
        appendLine("  $title")
        appendLine(THIN)
    }

    private fun StringBuilder.appendDeviceFlag(flag: DeviceFlag, triggered: Boolean) {
        val icon = if (triggered) "[✗]" else "[✓]"
        val sev  = flag.severity.name.padEnd(8)
        appendLine("  $icon  $sev  ${flag.title}")
        if (triggered) {
            appendLine("           ${flag.description}")
        }
    }

    private fun StringBuilder.appendAppRisk(app: AppRisk) {
        val risk = app.riskLevel.name.padEnd(8)
        appendLine("  ●  $risk  ${app.appName}")
        appendLine("     Package : ${app.packageName}")
        val badges = buildList {
            if (app.isKnownMalware) add("⚠ Known Malware")
            if (app.isSideloaded)   add("Sideloaded")
        }.joinToString(" · ")
        if (badges.isNotEmpty()) appendLine("     Flags   : $badges")
        if (app.reasons.isNotEmpty()) {
            appendLine("     Reasons : ${app.reasons.joinToString("; ")}")
        }
        if (app.dangerousPermissions.isNotEmpty()) {
            appendLine("     Perms   : ${app.dangerousPermissions.joinToString(", ")}")
        }
        appendLine()
    }

    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"
}
