package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.effectiveCorrelationId
import com.androdr.data.model.effectivePackageFromDescription
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Exports forensic timeline events as plaintext or CSV.
 * Output is strictly ASCII -- no Unicode characters.
 */
object TimelineExporter {

    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"

    @Suppress("LongMethod") // Report formatting assembles header, assessment, date groups, and footer
    fun formatPlaintext(
        events: List<ForensicTimelineEvent>,
        displayNames: Map<String, String> = emptyMap(),
        ruleGuidance: Map<String, String> = emptyMap()
    ): String = buildString {
        appendLine(RULE)
        appendLine("  AndroDR Forensic Timeline")
        appendLine("  Version: ${com.androdr.BuildConfig.VERSION_NAME}")
        appendLine("  Generated: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
        appendLine("  Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("  Device: ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("  Patch: ${Build.VERSION.SECURITY_PATCH}")
        // Deduplicate by description+package but include ALL severity levels
        val filtered = events
            .distinctBy { "${it.description}|${it.packageName}|${it.ruleId}" }

        appendLine("  Events: ${filtered.size}")
        appendLine(RULE)
        appendLine()

        if (filtered.isEmpty()) {
            appendLine("  No timeline events recorded.")
            appendLine()
            appendLine(RULE)
            return@buildString
        }

        // Phase A: telemetry events no longer carry severity. The exporter
        // reports totals only; phase B will partition by TelemetryRow vs.
        // FindingRow and report finding severity from the Finding itself.
        appendLine("  Total events: ${filtered.size}")
        val significantCount = 0

        // Assessment derived from rule guidance — the rules define threat severity,
        // not hardcoded category/severity checks in the formatter.
        val maxGuidancePriority = filtered
            .mapNotNull { ruleGuidance[it.ruleId].takeIf { g -> !g.isNullOrEmpty() } }
            .maxOfOrNull { guidancePriority(it) } ?: 0
        val assessment = when {
            maxGuidancePriority >= 3 -> "CRITICAL ACTIVITY DETECTED"
            maxGuidancePriority >= 1 || significantCount > 0 -> "REVIEW RECOMMENDED"
            else -> "NO CONCERNS"
        }
        // Phase A: no per-event severity. Severity rollup returns in phase B
        // once findings become a distinct TimelineRow variant.
        val severityParts = emptyList<String>()

        appendLine()
        appendLine("  ASSESSMENT: $assessment")
        if (severityParts.isNotEmpty()) {
            appendLine("  Severity: ${severityParts.joinToString(", ")}")
        }
        val pkgCount = filtered.map { it.packageName }.filter { it.isNotEmpty() }.distinct().size
        if (significantCount > 0) {
            appendLine("  $significantCount event(s) across $pkgCount package(s) require attention.")
        }
        appendLine()

        val sorted = filtered.sortedByDescending { it.startTimestamp }
        val dateFmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)
        var currentDate = ""
        for (event in sorted) {
            val date = if (event.startTimestamp > 0)
                dateFmt.format(Date(event.startTimestamp))
            else "Unknown"
            if (date != currentDate) {
                currentDate = date
                appendLine(THIN)
                appendLine("  $date")
                appendLine(THIN)
            }
            val time = if (event.startTimestamp > 0) {
                timeFmt.format(Date(event.startTimestamp))
            } else "??:??:??"
            appendLine("  $time  ${event.description}")
            if (event.appName.isNotEmpty() && event.appName != event.packageName) {
                appendLine("             App: ${event.appName} (${event.packageName})")
            } else if (event.packageName.isNotEmpty()) {
                val resolved = displayNames[event.packageName]
                if (resolved != null) {
                    appendLine("             App: $resolved (${event.packageName})")
                } else {
                    appendLine("             Package: ${event.packageName}")
                }
            }
            if (event.iocIndicator.isNotEmpty()) {
                appendLine("             IOC: ${event.iocIndicator} (${event.iocType})")
            }
            if (event.campaignName.isNotEmpty()) {
                appendLine("             Campaign: ${event.campaignName}")
            }
            if (event.apkHash.isNotEmpty()) {
                appendLine("             APK SHA-256: ${event.apkHash}")
            }
            if (event.details.isNotEmpty()) {
                appendLine("             ${event.details}")
            }
        }

        appendLine()
        appendLine(RULE)
        appendLine("  End of timeline / AndroDR")
        appendLine(RULE)
    }

    fun formatCsv(events: List<ForensicTimelineEvent>): String = buildString {
        // Column set mirrors the on-screen Timeline detail sheet plus the
        // clustering/correlation fields the UI uses to render cluster cards
        // and the Linked Evidence section. Without rule_id + correlation_id
        // + kind, a CSV consumer can't tell whether a row is a raw event
        // or a correlation signal, which rule produced it, or which other
        // rows share its cluster — the same information the Timeline UI
        // shows but previously dropped on export.
        appendLine(
            "timestamp,isodate,end_timestamp,end_isodate,kind,module,event,data,package," +
                "severity,rule_id,correlation_id,scan_result_id," +
                "ioc_indicator,ioc_type,ioc_source,campaign,mitre_technique,apk_hash,details"
        )

        val utcFmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }

        for (event in events.sortedBy { it.startTimestamp }) {
            val ts = event.startTimestamp.toString()
            val iso = if (event.startTimestamp > 0) utcFmt.format(Date(event.startTimestamp)) else ""
            val endTs = event.endTimestamp?.toString() ?: ""
            val endIso = event.endTimestamp?.let { if (it > 0) utcFmt.format(Date(it)) else "" } ?: ""
            val kind = csvEscape(event.kind)
            val module = csvEscape(event.source)
            val eventType = csvEscape(event.category)
            val data = csvEscape(event.description)
            // Same recovery for the package column: fall back to the
            // description-parsed package so legacy rows are not blank
            // in the export even before MIGRATION_13_14 has run.
            val pkg = csvEscape(
                event.packageName.takeIf { it.isNotBlank() }
                    ?: event.effectivePackageFromDescription().orEmpty()
            )
            // Phase A: severity column kept in CSV header for backward
            // compatibility; always empty since telemetry has no severity.
            val sev = ""
            val ruleId = csvEscape(event.ruleId)
            // Prefer the stamped correlationId; fall back to the same
            // read-time key the Timeline UI uses for clustering. The
            // `effectiveCorrelationId()` helper also parses legacy rows
            // whose packageName field is empty but whose description
            // begins with a dotted package like "com.x.y used READ_...".
            // This keeps the CSV consistent with what the app renders on
            // screen, even for rows that predate the migration.
            val correlationId = csvEscape(event.effectiveCorrelationId())
            val scanId = event.scanResultId.toString()
            val ioc = csvEscape(event.iocIndicator)
            val iocType = csvEscape(event.iocType)
            val iocSrc = csvEscape(event.iocSource)
            val campaign = csvEscape(event.campaignName)
            val mitre = csvEscape(event.attackTechniqueId)
            val hash = csvEscape(event.apkHash)
            val details = csvEscape(event.details)
            @Suppress("MaxLineLength") // CSV row must be a single appendLine call
            appendLine("$ts,$iso,$endTs,$endIso,$kind,$module,$eventType,$data,$pkg,$sev,$ruleId,$correlationId,$scanId,$ioc,$iocType,$iocSrc,$campaign,$mitre,$hash,$details")
        }
    }

    private fun guidancePriority(guidance: String): Int =
        GuidanceUtils.guidancePriority(guidance)

    private fun csvEscape(value: String): String {
        // Prevent CSV formula injection (cells starting with =, +, -, @, \t, \r)
        val sanitized = if (value.isNotEmpty() && value[0] in setOf('=', '+', '-', '@', '\t', '\r')) {
            "'" + value
        } else value
        return if (sanitized.contains(',') || sanitized.contains('"') || sanitized.contains('\n')) {
            "\"${sanitized.replace("\"", "\"\"")}\""
        } else sanitized
    }
}
