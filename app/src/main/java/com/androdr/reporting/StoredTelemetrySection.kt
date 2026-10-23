package com.androdr.reporting

import com.androdr.data.model.CivilDay
import com.androdr.data.db.ServiceSummary
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.DecodedRecord
import com.androdr.sigma.LiveRecordBuilders
import com.androdr.sigma.TimePrecision
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The report's TELEMETRY SECTION: the scan's own stored records, one generic section per service,
 * and the application log. Kept beside the formatter so each part can be read on its own.
 */

/**
 * This scan's own stored telemetry, one generic section per service, streamed record by
 * record. The state line says what the store holds for the scan, so a report with no (or only
 * some) telemetry says why: NONE, PARTIAL_RETENTION or FAILED (spec §7).
 */
internal suspend fun ReportOut.appendStoredTelemetry(
    scan: ScanResult,
    services: List<ServiceSummary>,
    telemetry: StoredTelemetrySource,
) {
    appendLine("  ${telemetryLine(scan.telemetryState, services.sumOf { it.records }, services.size)}")
    appendLine()
    val timeFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
    services.forEach { service ->
        section("${ReportFormatter.STORED_TELEMETRY_SECTION}: ${service.service} (${service.records} record(s))")
        if (service.service == LiveRecordBuilders.DNS_MONITOR && scan.source == TelemetrySource.LIVE_SCAN) {
            appendLine(ReportFormatter.DNS_LIVE_NOTE)
        }
        telemetry.forEach(scan.id, service.service) { r -> appendRecord(r, timeFmt) }
    }
}

private fun ReportOut.appendRecord(r: DecodedRecord, timeFmt: SimpleDateFormat) {
    val head = StringBuilder("  [").append(r.ordinal).append("] captured ").append(timeFmt.format(Date(r.capturedAt)))
    r.eventTime?.let { t ->
        // A day-precision time is a calendar date stored as its UTC midnight (R32): read it in UTC.
        val event = if (r.precision == TimePrecision.DAY) CivilDay.format(t) else timeFmt.format(Date(t))
        head.append("  event ").append(event)
    }
    r.category?.let { head.append("  (").append(it).append(')') }
    appendLine(head)
    val fields = r.fields
    if (fields == null) {
        appendLine("     (unreadable: this record's stored body could not be decoded)")
        return
    }
    fields.forEach { (key, value) -> appendLine("     $key: ${renderValue(value)}") }
}

/** A field value as text. Escaping is applied to the whole line by [ReportOut], once. */
private fun renderValue(value: Any?): String = when (value) {
    null -> "null"
    is Map<*, *> -> value.entries.joinToString(", ", "{", "}") { (k, v) -> "$k: ${renderValue(v)}" }
    is Collection<*> -> value.joinToString(", ", "[", "]") { renderValue(it) }
    is Array<*> -> value.joinToString(", ", "[", "]") { renderValue(it) }
    else -> value.toString()
}

/** The app's own log, captured when the report is exported (not part of the scan). */
internal fun ReportOut.appendLog(logLines: List<String>) {
    section("APPLICATION LOG  (${logLines.size} lines, captured at export)")
    if (logLines.isEmpty()) {
        appendLine("  (no log lines captured)")
    } else {
        logLines.forEach { line -> appendLine("  $line") }
    }
}
