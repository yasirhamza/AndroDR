package com.androdr.reporting

import com.androdr.data.db.FindingsMigration
import com.androdr.data.model.AlertStatus
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.AlertReportGroup
import com.androdr.data.repo.AlertSample
import com.androdr.data.store.DecodedRecord
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The alert groups a report lists, streamed by status (spec §5.4, review I5): grouped and ordered as
 * the Dashboard lists them, each with exact counts and at most [ALERT_SAMPLE_DISPLAY_LIMIT] of its most
 * recent alerts. [NONE] lists none.
 */
fun interface AlertReportSource {
    suspend fun forEachGroup(status: AlertStatus, block: suspend (AlertReportGroup) -> Unit)

    companion object {
        val NONE = AlertReportSource { _, _ -> }
    }
}

/**
 * Alerts listed per report group (a display bound, spec §5.5: it bounds what is shown, never what is
 * stored; every alert is counted in its group's header and "…and K more" line).
 */
const val ALERT_SAMPLE_DISPLAY_LIMIT = 20

/**
 * The device's lasting alerts: OPEN groups with each alert's opening scan, then CLOSED groups with
 * each alert's closing time, note and credential flag. Streamed group page by group page, never all
 * in memory. This scan's state findings are the sections above.
 */
internal suspend fun ReportOut.appendAlerts(alerts: AlertReportSource) {
    section("ALERTS")
    appendLine("  Alerts stay open until a person closes them; this scan's state findings are listed above.")
    appendLine("  Grouped by rule and matched value (or app); each group lists its $ALERT_SAMPLE_DISPLAY_LIMIT " +
        "most recent alerts.")
    appendLine()
    appendLine("  Open alerts:")
    var open = 0
    alerts.forEachGroup(AlertStatus.OPEN) { g ->
        open += g.row.count
        appendGroupHead(g)
        appendLine("           first opened ${reportTime(g.row.firstOpenedAt)}, " +
            "last activity ${reportTime(g.row.lastActivityAt)}")
        for (s in g.samples) {
            appendLine("         - opened ${reportTime(s.alert.openedAt)} by ${openedBy(s)}, " +
                "last activity ${reportTime(s.alert.lastActivityAt)}")
            appendMatchedRecord(s)
        }
        appendMore(g)
    }
    appendLine(if (open == 0) "  (none)" else "  $open open alert(s) in total")
    appendLine()
    appendLine("  Closed alerts:")
    var closed = 0
    alerts.forEachGroup(AlertStatus.CLOSED) { g ->
        closed += g.row.count
        appendGroupHead(g)
        appendLine("           last closed ${g.row.lastClosedAt?.let(::reportTime) ?: "unknown"}, " +
            "${g.row.withCredential} of ${g.row.count} closed with the device credential")
        for (s in g.samples) {
            appendLine("         - ${closing(s)}")
            appendMatchedRecord(s)
        }
        appendMore(g)
    }
    appendLine(if (closed == 0) "  (none)" else "  $closed closed alert(s) in total")
}

private fun ReportOut.appendGroupHead(g: AlertReportGroup) {
    val sample = g.samples.firstOrNull()?.alert
    val title = sample?.evidence?.title?.takeIf { it.isNotBlank() } ?: g.row.ruleId
    val level = sample?.level?.uppercase().orEmpty().padEnd(8)
    val value = g.row.matchedValue.takeIf { it.isNotEmpty() }?.let { " — $it" }.orEmpty()
    appendLine("  [!!]  $level  $title$value  (${g.row.ruleId}) · ${g.row.count} alert(s)")
}

private fun ReportOut.appendMore(g: AlertReportGroup) {
    val more = g.row.count - g.samples.size
    if (more > 0) appendLine("         …and $more more alert(s) of this group")
}

/** Who opened the alert: its opening scan and that scan's source, or that the scan was deleted. */
private fun openedBy(s: AlertSample): String {
    val source = when (s.openedBy) {
        TelemetrySource.LIVE_SCAN -> "live scan"
        TelemetrySource.BUGREPORT_IMPORT -> "bug report import"
        TelemetrySource.INTRUSION_LOG_IMPORT -> "intrusion log import"
        null -> "scan deleted"
    }
    return "scan ${s.alert.openedScanId} ($source)"
}

/** A closed alert's line: an automatic (migrated) closure says so; a person's closure gives note and flag. */
private fun closing(s: AlertSample): String {
    val a = s.alert
    val at = a.closedAt?.let(::reportTime) ?: "unknown"
    if (a.closedReason == FindingsMigration.MIGRATED_CLOSED_REASON) {
        return "closed automatically $at (migrated, older than 30 days)"
    }
    val note = a.closedReason?.takeIf { it.isNotBlank() } ?: "(none)"
    val credential = if (a.closedWithCredential) "yes" else "no"
    return "closed $at · note: $note · closed with device credential: $credential"
}

/** The alert's matched fact (its "Matched record"), which the alert pins whatever happens to scans. */
private fun ReportOut.appendMatchedRecord(s: AlertSample) {
    if (s.alert.recordId == null) return
    val record: DecodedRecord? = s.record
    val fields = record?.fields
    if (fields == null) {
        appendLine("           matched record: (not readable)")
        return
    }
    appendLine("           matched record (${record.service}): " +
        fields.entries.joinToString("; ") { (k, v) -> "$k=${renderValue(v)}" })
}

private fun reportTime(ts: Long): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(ts))
