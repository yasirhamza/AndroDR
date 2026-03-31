package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.ForensicTimelineEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object TimelineExporter {

    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"

    @Suppress("LongMethod") // Report formatting assembles header, filters, date groups, and footer
    fun formatPlaintext(events: List<ForensicTimelineEvent>): String = buildString {
        appendLine(RULE)
        appendLine("  AndroDR Forensic Timeline")
        appendLine("  Version: ${com.androdr.BuildConfig.VERSION_NAME}")
        appendLine("  Generated: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
        appendLine("  Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("  Device: ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("  Events: ${events.size}")
        appendLine(RULE)
        appendLine()

        // Exclude informational events and deduplicate by description+package
        val filtered = events
            .filter { it.severity.uppercase() != "INFORMATIONAL" }
            .distinctBy { "${it.description}|${it.packageName}|${it.ruleId}" }

        if (filtered.isEmpty()) {
            appendLine("  No significant timeline events recorded.")
            appendLine("  (${events.size} informational events excluded)")
            appendLine()
            appendLine(RULE)
            return@buildString
        }

        appendLine("  Significant events: ${filtered.size}")
        if (events.size > filtered.size) {
            appendLine("  (${events.size - filtered.size} informational events excluded)")
        }
        appendLine()

        val sorted = filtered.sortedByDescending { it.timestamp }
        val dateFmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)
        var currentDate = ""
        for (event in sorted) {
            val date = if (event.timestamp > 0)
                dateFmt.format(Date(event.timestamp))
            else "Unknown"
            if (date != currentDate) {
                currentDate = date
                appendLine(THIN)
                appendLine("  $date")
                appendLine(THIN)
            }
            val time = if (event.timestamp > 0) {
                timeFmt.format(Date(event.timestamp))
            } else "??:??:??"
            val sev = event.severity.uppercase().padEnd(8)
            appendLine("  [$sev] $time  ${event.description}")
            if (event.appName.isNotEmpty() && event.appName != event.packageName) {
                appendLine("             App: ${event.appName} (${event.packageName})")
            } else if (event.packageName.isNotEmpty()) {
                appendLine("             Package: ${event.packageName}")
            }
            if (event.iocIndicator.isNotEmpty()) {
                appendLine("             IOC: ${event.iocIndicator} (${event.iocType})")
            }
            if (event.campaignName.isNotEmpty()) {
                appendLine("             Campaign: ${event.campaignName}")
            }
            if (event.details.isNotEmpty()) {
                appendLine("             ${event.details}")
            }
        }

        appendLine()
        appendLine(RULE)
        appendLine("  End of timeline \u00b7 AndroDR")
        appendLine(RULE)
    }

    fun formatCsv(events: List<ForensicTimelineEvent>): String = buildString {
        appendLine(
            "timestamp,isodate,module,event,data,package,severity," +
                "ioc_indicator,ioc_type,ioc_source,campaign,mitre_technique,details"
        )

        val utcFmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }

        for (event in events.sortedBy { it.timestamp }) {
            val ts = event.timestamp.toString()
            val iso = if (event.timestamp > 0) utcFmt.format(Date(event.timestamp)) else ""
            val module = csvEscape(event.source)
            val eventType = csvEscape(event.category)
            val data = csvEscape(event.description)
            val pkg = csvEscape(event.packageName)
            val sev = event.severity
            val ioc = csvEscape(event.iocIndicator)
            val iocType = csvEscape(event.iocType)
            val iocSrc = csvEscape(event.iocSource)
            val campaign = csvEscape(event.campaignName)
            val mitre = csvEscape(event.attackTechniqueId)
            val details = csvEscape(event.details)
            appendLine("$ts,$iso,$module,$eventType,$data,$pkg,$sev,$ioc,$iocType,$iocSrc,$campaign,$mitre,$details")
        }
    }

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
