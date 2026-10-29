package com.androdr.reporting

import com.androdr.data.db.ServiceSummary
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import java.text.NumberFormat
import java.util.Locale

/**
 * What the History sheet shows for a scan (spec §7: "The History sheet shows a summary"): the
 * verdict counts and which telemetry this scan stored. The full report is never built in memory
 * for the sheet; it is exported through [ReportExporter] like every other report.
 */
data class ReportSummary(
    val source: TelemetrySource,
    val overallRisk: String,
    val appIssues: Int,
    val deviceIssues: Int,
    val warningSigns: Int,
    val checksNotRun: Int,
    val failedScanners: Int,
    val telemetryState: TelemetryState,
    val services: List<ServiceSummary>,
) {
    val records: Int get() = services.sumOf { it.records }

    /** The sheet's lines in display order; counts use the locale's digit grouping ([groupedCount]). */
    fun lines(): List<String> = buildList {
        fun n(count: Int) = groupedCount(count.toLong())
        add("Overall risk: $overallRisk")
        when (source) {
            TelemetrySource.LIVE_SCAN -> Unit
            TelemetrySource.BUGREPORT_IMPORT -> add("Source: imported bug report")
            TelemetrySource.INTRUSION_LOG_IMPORT -> add("Source: imported intrusion log")
        }
        add("App issues: ${n(appIssues)}")
        add("Device settings needing attention: ${n(deviceIssues)}")
        add("Warning signs that add up: ${n(warningSigns)}")
        if (checksNotRun > 0) add("Checks that could not run: ${n(checksNotRun)}")
        if (failedScanners > 0) add("Scanners that failed: ${n(failedScanners)}")
        add(telemetryLine(telemetryState, records, services.size, ::n))
        services.forEach { add("  ${serviceLabel(it.service)} (${it.service}): ${n(it.records)} record(s)") }
        add("Export the report for the full findings and telemetry.")
    }
}

/**
 * What a full export of one scan carries (spec §7: the export dialog states the record count, the
 * size, and the sensitive categories included). [bytes] is the decoded size of the stored records;
 * the text report is somewhat larger.
 */
data class ExportEstimate(val records: Long, val bytes: Long, val categories: List<String>) {
    /** The dialog's sentence. */
    fun text(): String = if (records == 0L) {
        "This scan has no stored telemetry; the report carries its findings only."
    } else {
        "Includes ${groupedCount(records)} telemetry record(s) (about ${humanBytes(bytes)}) from: " +
            "${categories.joinToString(", ")}. $SENSITIVE"
    }

    /**
     * The telemetry (JSONL) export dialog's sentence: the same count, size and categories. [bytes] is
     * the decoded records' size: approximate, before compression, without each line's envelope.
     */
    fun jsonlText(): String = if (records == 0L) {
        "This scan has no stored telemetry; the export would be empty."
    } else {
        "One line per record: ${groupedCount(records)} telemetry record(s) (about ${humanBytes(bytes)} of " +
            "records before compression; each line also carries a short envelope) from: " +
            "${categories.joinToString(", ")}. $SENSITIVE"
    }

    companion object {
        val NONE = ExportEstimate(0, 0, emptyList())
        private const val SENSITIVE =
            "This can reveal the apps on the phone and what they did; share it only with someone you trust."
    }
}

/**
 * The one line that says what the store holds for a scan, shared by the report and the summary.
 * Each state has its own line, so a report missing telemetry says why (spec §7). [count] formats the
 * numbers: plain in the exported report, grouped on the History sheet.
 */
internal fun telemetryLine(
    state: TelemetryState,
    recordCount: Int,
    serviceCount: Int,
    count: (Int) -> String = { it.toString() },
): String {
    val records = count(recordCount)
    val services = count(serviceCount)
    return when (state) {
        TelemetryState.STORED ->
            "Stored telemetry: $records record(s) from $services source(s), captured with this scan."
        TelemetryState.PARTIAL_RETENTION -> "${ReportFormatter.TELEMETRY_PARTIAL} $records record(s) remain."
        TelemetryState.NONE -> ReportFormatter.TELEMETRY_NONE
        // Chunks persisted before an evaluate-only fallback stay: never claim nothing was saved.
        TelemetryState.FAILED -> if (recordCount == 0) {
            ReportFormatter.TELEMETRY_FAILED
        } else {
            "${ReportFormatter.TELEMETRY_FAILED_PARTWAY} $records record(s) were stored before it failed; " +
                "the rest were checked but not saved."
        }
        // Retention later removed records: the count left is neither "stored before it failed" nor zero saved.
        TelemetryState.FAILED_PARTIAL_RETENTION ->
            "${ReportFormatter.TELEMETRY_FAILED_RETAINED} $records record(s) remain."
    }
}

/** Plain words for each telemetry service: the export notice's sensitive categories. */
private val SERVICE_LABELS = mapOf(
    "app_scanner" to "installed apps",
    "device_auditor" to "device settings",
    "dns_monitor" to "DNS lookups",
    "process_monitor" to "running processes",
    "file_scanner" to "files",
    "receiver_audit" to "app receivers",
    "accessibility_audit" to "accessibility services",
    "appops_audit" to "app permissions in use",
    "network_monitor" to "network connections",
    "tombstone_parser" to "app crash records",
    "wakelock_parser" to "wakelock records",
    "battery_daily" to "battery usage history",
    "package_install_history" to "app install history",
    "platform_compat" to "platform compatibility changes",
    "db_info" to "database access records",
    "security_log" to "security log entries",
    "timeline" to "system timeline events",
    "usage_stats" to "app usage history",
    "system_property" to "system properties",
    "adb_audit" to "ADB connection records",
    "activity_audit" to "app activity records",
)

/** [service] in plain words, or its own name when it has none. */
internal fun serviceLabel(service: String): String = SERVICE_LABELS[service] ?: service

private const val KIB = 1024.0

/** [n] with [locale]'s digit grouping, e.g. "125,000" in Locale.US (battery B4). */
internal fun groupedCount(n: Long, locale: Locale = Locale.getDefault()): String =
    NumberFormat.getIntegerInstance(locale).format(n)

/** [bytes] in plain words (bytes, KB or MB). */
internal fun humanBytes(bytes: Long): String = when {
    bytes < KIB -> "$bytes bytes"
    bytes < KIB * KIB -> String.format(Locale.US, "%.1f KB", bytes / KIB)
    else -> String.format(Locale.US, "%.1f MB", bytes / (KIB * KIB))
}
