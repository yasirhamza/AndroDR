package com.androdr.reporting

import com.androdr.data.model.AlertStatus
import com.androdr.data.repo.AlertView
import com.androdr.data.store.DecodedRecord
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** The alerts a report lists, streamed by status (spec §5.4); [NONE] lists none. */
fun interface AlertReportSource {
    /** Each alert with [status] and its matched record (null when it has none or it is unreadable). */
    suspend fun forEach(status: AlertStatus, block: suspend (AlertView, DecodedRecord?) -> Unit)

    companion object {
        val NONE = AlertReportSource { _, _ -> }
    }
}

/**
 * The device's lasting alerts: OPEN ones with their opening scan, then CLOSED ones with the
 * closing time, note and credential flag. Streamed page by page ([AlertReportSource]), never all
 * in memory. This scan's state findings are the sections above.
 */
internal suspend fun ReportOut.appendAlerts(alerts: AlertReportSource) {
    section("ALERTS")
    appendLine("  Alerts stay open until a person closes them; this scan's state findings are listed above.")
    appendLine()
    appendLine("  Open alerts:")
    var open = 0
    alerts.forEach(AlertStatus.OPEN) { a, record ->
        open++
        appendAlertHead(a)
        appendLine("           opened ${reportTime(a.openedAt)} by scan ${a.openedScanId}, " +
            "last activity ${reportTime(a.lastActivityAt)}")
        appendMatchedRecord(a, record)
    }
    if (open == 0) appendLine("  (none)")
    appendLine()
    appendLine("  Closed alerts:")
    var closed = 0
    alerts.forEach(AlertStatus.CLOSED) { a, record ->
        closed++
        appendAlertHead(a)
        appendMatchedRecord(a, record)
        val note = a.closedReason?.takeIf { it.isNotBlank() } ?: "(none)"
        val credential = if (a.closedWithCredential) "yes" else "no"
        appendLine("           closed ${a.closedAt?.let(::reportTime) ?: "unknown"} · note: $note · " +
            "closed with device credential: $credential")
    }
    if (closed == 0) appendLine("  (none)")
}

private fun ReportOut.appendAlertHead(a: AlertView) {
    val title = a.evidence?.title?.takeIf { it.isNotBlank() } ?: a.ruleId
    val value = a.matchedValue.takeIf { it.isNotEmpty() }?.let { " — $it" }.orEmpty()
    appendLine("  [!!]  ${a.level.uppercase().padEnd(8)}  $title$value  (${a.ruleId})")
}

/** The alert's matched fact (its "Matched record"), which the alert pins whatever happens to scans. */
private fun ReportOut.appendMatchedRecord(a: AlertView, record: DecodedRecord?) {
    if (a.recordId == null) return
    val fields = record?.fields
    if (fields == null) {
        appendLine("           matched record: (not readable)")
        return
    }
    appendLine("           matched record (${record.service}): " +
        fields.entries.joinToString("; ") { (k, v) -> "$k=${renderValue(v)}" })
}

private fun reportTime(ts: Long): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(ts))
