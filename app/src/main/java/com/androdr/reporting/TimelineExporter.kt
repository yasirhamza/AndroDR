package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.ForensicTimelineEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object TimelineExporter {

    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"
    private val timestampFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
    private val dateFmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)

    fun formatPlaintext(events: List<ForensicTimelineEvent>): String = buildString {
        appendLine(RULE)
        appendLine("  AndroDR Forensic Timeline")
        appendLine("  Generated: ${timestampFmt.format(Date())}")
        appendLine("  Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        appendLine("  Device: ${Build.MANUFACTURER} ${Build.MODEL}")
        appendLine("  Events: ${events.size}")
        appendLine(RULE)
        appendLine()

        if (events.isEmpty()) {
            appendLine("  No timeline events recorded.")
            appendLine()
            appendLine(RULE)
            return@buildString
        }

        val sorted = events.sortedByDescending { it.timestamp }
        var currentDate = ""
        for (event in sorted) {
            val date = if (event.timestamp > 0) dateFmt.format(Date(event.timestamp)) else "Unknown"
            if (date != currentDate) {
                currentDate = date
                appendLine(THIN)
                appendLine("  $date")
                appendLine(THIN)
            }
            val time = if (event.timestamp > 0) {
                SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(event.timestamp))
            } else "??:??:??"
            val sev = event.severity.uppercase().padEnd(8)
            appendLine("  [$sev] $time  ${event.description}")
            if (event.packageName.isNotEmpty()) {
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
        appendLine("timestamp,isodate,module,event,data,package,severity,ioc_indicator,ioc_type,campaign")

        for (event in events.sortedBy { it.timestamp }) {
            val ts = event.timestamp.toString()
            val iso = if (event.timestamp > 0) timestampFmt.format(Date(event.timestamp)) else ""
            val module = csvEscape(event.source)
            val eventType = csvEscape(event.category)
            val data = csvEscape(event.description)
            val pkg = csvEscape(event.packageName)
            val sev = event.severity
            val ioc = csvEscape(event.iocIndicator)
            val iocType = csvEscape(event.iocType)
            val campaign = csvEscape(event.campaignName)
            appendLine("$ts,$iso,$module,$eventType,$data,$pkg,$sev,$ioc,$iocType,$campaign")
        }
    }

    private fun csvEscape(value: String): String =
        if (value.contains(',') || value.contains('"') || value.contains('\n')) {
            "\"${value.replace("\"", "\"\"")}\""
        } else value
}
