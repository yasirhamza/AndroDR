package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.TimelineEvent
import com.androdr.sigma.Finding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Formats bug report analysis results (SIGMA findings, legacy findings,
 * and timeline events) into a human-readable plaintext report suitable
 * for sharing. Output is strictly ASCII.
 */
object TimelineFormatter {

    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"

    @Suppress("LongMethod") // Report formatting assembles header, verdict, grouped findings,
    // timeline, and inventory in a specific order.
    fun formatTimeline(
        timeline: List<TimelineEvent>,
        findings: List<Finding>,
        hashByPkg: Map<String, String> = emptyMap(),
        displayNames: Map<String, String> = emptyMap()
    ): String = buildString {
        val generated = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

        appendLine(RULE)
        appendLine("  AndroDR Bug Report Analysis Timeline")
        appendLine("  Version   : ${com.androdr.BuildConfig.VERSION_NAME}")
        appendLine("  Generated : $generated")
        appendLine("  Android   : ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("  Device    : ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("  Patch     : ${Build.VERSION.SECURITY_PATCH}")
        appendLine(RULE)
        appendLine()

        // -- Verdict --------------------------------------------------------------
        val triggeredFindings = findings.filter { it.triggered }
        val critical = triggeredFindings.count { it.level.equals("critical", true) }
        val high = triggeredFindings.count { it.level.equals("high", true) }
        val medium = triggeredFindings.count { it.level.equals("medium", true) }
        val verdict = when {
            critical > 0 -> "CRITICAL THREATS DETECTED"
            high > 0 -> "ISSUES FOUND"
            medium > 0 -> "ISSUES FOUND"
            triggeredFindings.isNotEmpty() -> "INFORMATIONAL ONLY"
            else -> "CLEAN"
        }
        appendLine("  ANALYSIS VERDICT: $verdict")
        appendLine("  SIGMA findings: $critical critical, $high high, $medium medium")
        appendLine()

        // -- SIGMA findings section -----------------------------------------------
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
                            val name = displayNames[pkg]
                            if (name != null) {
                                appendLine("    Package: $name ($pkg)")
                            } else {
                                appendLine("    Package: $pkg")
                            }
                            hashByPkg[pkg]?.let { appendLine("    APK SHA-256: $it") }
                        }
                    } else {
                        appendLine("    ${packages.size} apps: ${packages.take(5).joinToString(", ")}" +
                            if (packages.size > 5) ", ..." else "")
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
                val name = displayNames[pkg]
                if (name != null) {
                    appendLine("  $name")
                    appendLine("    Package: $pkg")
                } else {
                    appendLine("  $pkg")
                }
                appendLine("    SHA-256: $hash")
            }
            appendLine()
        }

        appendLine(RULE)
        appendLine("  End of analysis - AndroDR")
        appendLine(RULE)
    }

    private fun severityOrdinal(level: String): Int = when (level.lowercase()) {
        "critical" -> 3; "high" -> 2; "medium" -> 1; else -> 0
    }
}
