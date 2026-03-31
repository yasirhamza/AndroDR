package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.TimelineEvent
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import com.androdr.sigma.Finding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Formats bug report analysis results (SIGMA findings, legacy findings,
 * and timeline events) into a human-readable plaintext report suitable
 * for sharing.
 */
object TimelineFormatter {

    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"

    fun formatTimeline(
        timeline: List<TimelineEvent>,
        legacyFindings: List<BugReportFinding>,
        findings: List<Finding>
    ): String = buildString {
        val generated = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

        appendLine(RULE)
        appendLine("  AndroDR Bug Report Analysis Timeline")
        appendLine("  Generated: $generated")
        appendLine("  Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("  Device: ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("  Patch: ${Build.VERSION.SECURITY_PATCH}")
        appendLine(RULE)
        appendLine()

        // SIGMA findings section
        val triggeredFindings = findings.filter { it.triggered }
        appendLine(THIN)
        appendLine("  FINDINGS (${triggeredFindings.size})")
        appendLine(THIN)
        if (triggeredFindings.isEmpty()) {
            appendLine("  No SIGMA rule findings triggered.")
        } else {
            triggeredFindings.sortedByDescending { severityOrdinal(it.level) }.forEach { f ->
                appendLine("  [${f.level.uppercase()}] ${f.title}")
                if (f.description.isNotEmpty()) {
                    appendLine("    ${f.description}")
                }
                if (f.remediation.isNotEmpty()) {
                    appendLine("    Action: ${f.remediation.first()}")
                }
                appendLine()
            }
        }

        // Legacy findings section (from regex scanning)
        if (legacyFindings.isNotEmpty()) {
            appendLine(THIN)
            appendLine("  PATTERN SCAN (${legacyFindings.size})")
            appendLine(THIN)
            legacyFindings.forEach { f ->
                appendLine("  [${f.severity}] ${f.category}: ${f.description}")
            }
            appendLine()
        }

        // Timeline section
        if (timeline.isNotEmpty()) {
            appendLine(THIN)
            appendLine("  TIMELINE (${timeline.size} events)")
            appendLine(THIN)
            timeline.sortedBy { it.timestamp }.forEach { e ->
                val sev = e.severity.uppercase().padEnd(8)
                appendLine("  $sev  [${e.source}] ${e.description}")
            }
            appendLine()
        }

        appendLine(RULE)
        appendLine("  End of analysis \u00b7 AndroDR")
        appendLine(RULE)
    }

    private fun severityOrdinal(level: String): Int = when (level.lowercase()) {
        "critical" -> 3; "high" -> 2; "medium" -> 1; else -> 0
    }
}
