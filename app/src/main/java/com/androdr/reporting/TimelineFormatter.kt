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
 * for sharing. Every line is escaped with [escapeForReport].
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
        displayNames: Map<String, String> = emptyMap(),
        versionName: String
    ): String = buildString {
        val generated = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

        line(RULE)
        line("  AndroDR Bug Report Analysis Timeline")
        line("  Version   : $versionName")
        line("  Generated : $generated")
        line("  Android   : ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        line("  Device    : ${Build.MANUFACTURER} ${Build.MODEL}")
        line("  Patch     : ${Build.VERSION.SECURITY_PATCH}")
        line(RULE)
        line()

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
        line("  ANALYSIS VERDICT: $verdict")
        line("  SIGMA findings: $critical critical, $high high, $medium medium")
        line()

        // -- SIGMA findings section -----------------------------------------------
        line(THIN)
        line("  FINDINGS (${triggeredFindings.size})")
        line(THIN)
        if (triggeredFindings.isEmpty()) {
            line("  No SIGMA rule findings triggered.")
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
                line("  [${f.level.uppercase()}] ${f.title}")
                if (packages.isNotEmpty()) {
                    if (packages.size <= 3) {
                        packages.forEach { pkg ->
                            val name = displayNames[pkg]
                            if (name != null) {
                                line("    Package: $name ($pkg)")
                            } else {
                                line("    Package: $pkg")
                            }
                            hashByPkg[pkg]?.let { line("    APK SHA-256: $it") }
                        }
                    } else {
                        line("    ${packages.size} apps: ${packages.take(5).joinToString(", ")}" +
                            if (packages.size > 5) ", ..." else "")
                    }
                }
                if (f.description.isNotEmpty()) {
                    line("    ${f.description}")
                }
                if (f.remediation.isNotEmpty()) {
                    line("    Action: ${f.remediation.first()}")
                }
                line()
            }
        }

        // Timeline section
        if (timeline.isNotEmpty()) {
            line(THIN)
            line("  TIMELINE (${timeline.size} events)")
            line(THIN)
            timeline.sortedBy { it.timestamp }.forEach { e ->
                val sev = e.severity.uppercase().padEnd(8)
                line("  $sev  [${e.source}] ${e.description}")
            }
            line()
        }

        // APP HASH INVENTORY
        if (hashByPkg.isNotEmpty()) {
            line(THIN)
            line("  APP HASH INVENTORY (${hashByPkg.size} apps)")
            line(THIN)
            hashByPkg.entries.sortedBy { it.key }.forEach { (pkg, hash) ->
                val name = displayNames[pkg]
                if (name != null) {
                    line("  $name")
                    line("    Package: $pkg")
                } else {
                    line("  $pkg")
                }
                line("    SHA-256: $hash")
            }
            line()
        }

        line(RULE)
        line("  End of analysis - AndroDR")
        line(RULE)
    }

    /**
     * One line of the export, through [escapeForReport] (spec §7, R3): package, process and app
     * names and event descriptions come from the bug report, so none may break a line or reverse text.
     */
    private fun StringBuilder.line(text: String = "") {
        append(escapeForReport(text)).append('\n')
    }

    private fun severityOrdinal(level: String): Int = when (level.lowercase()) {
        "critical" -> 3; "high" -> 2; "medium" -> 1; else -> 0
    }
}
