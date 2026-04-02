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

    @Suppress("LongMethod") // Report formatting assembles header, grouped findings, legacy, and timeline
    fun formatTimeline(
        timeline: List<TimelineEvent>,
        legacyFindings: List<BugReportFinding>,
        findings: List<Finding>,
        hashByPkg: Map<String, String> = emptyMap()
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
            // Group identical findings by title+level to reduce noise
            val grouped = triggeredFindings
                .sortedByDescending { severityOrdinal(it.level) }
                .groupBy { "${it.level}|${it.title}" }
            grouped.values.forEach { group ->
                val f = group.first()
                val packages = group.mapNotNull {
                    it.matchContext["package_name"]?.takeIf { p -> p.isNotEmpty() }
                }.distinct()
                appendLine("  [${f.level.uppercase()}] ${f.title}")
                if (packages.isNotEmpty()) {
                    if (packages.size <= 3) {
                        packages.forEach { pkg ->
                            appendLine("    Package: $pkg")
                            hashByPkg[pkg]?.let { appendLine("    APK SHA-256: $it") }
                        }
                    } else {
                        appendLine("    ${packages.size} apps: ${packages.take(5).joinToString(", ")}" +
                            if (packages.size > 5) ", ..." else "")
                        // Show hashes for multi-package groups in inventory
                    }
                }
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

        // APP HASH INVENTORY
        if (hashByPkg.isNotEmpty()) {
            appendLine(THIN)
            appendLine("  APP HASH INVENTORY (${hashByPkg.size} apps)")
            appendLine(THIN)
            hashByPkg.entries.sortedBy { it.key }.forEach { (pkg, hash) ->
                appendLine("  $pkg")
                appendLine("    SHA-256: $hash")
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
