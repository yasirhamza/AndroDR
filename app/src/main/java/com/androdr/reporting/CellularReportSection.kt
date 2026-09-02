package com.androdr.reporting

import com.androdr.cellular.CellularRedaction
import com.androdr.cellular.CellularState
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.reporting.ReportFormatter.section
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The cellular blocks of the plaintext report: Tier 1 findings and the radio
 * telemetry behind them.
 *
 * Kept apart from [ReportFormatter] because the radio plane is the one part
 * of the report with its own redaction rule ([CellularRedaction]) and its own
 * time series; every value printed here has to be checked against that rule,
 * and that is easier to see in one place than spread through a 700-line
 * formatter. Pure, like the rest of the formatter.
 */
internal object CellularReportSection {

    /**
     * Radio state observed at export time.
     *
     * Recorded even when nothing fired, for two reasons. A report that shows
     * only anomalies cannot distinguish "the radio was clean" from "the
     * monitor was never running" — and on this feature that difference is
     * real, because cell info comes back EMPTY rather than erroring when the
     * caller is not permitted to read it. The delivery count is the evidence
     * the monitor was alive.
     *
     * Redacted like every other handoff path: condition, not tower identity.
     */
    internal fun StringBuilder.appendCellularTelemetry(
        snapshot: CellularSnapshot?,
        deliveries: Int,
        duplicates: Int,
        history: List<CellularSnapshot>,
    ) {
        section("CELLULAR TELEMETRY (TIER 1)")
        if (snapshot == null) {
            appendLine("  No radio telemetry captured this session.")
            appendLine("  Either the monitor was not running, or no serving cell was observed.")
            appendLine()
            return
        }
        // Deliveries that repeated the previous observation are counted but
        // not recorded, so the two numbers legitimately differ; say so rather
        // than let the reader wonder where the missing rows went.
        val suppressed = if (duplicates > 0) {
            " ($duplicates duplicate deliveries not recorded; ${deliveries - duplicates} distinct)"
        } else {
            ""
        }
        appendLine("  Radio updates delivered this session: $deliveries$suppressed")
        appendLine("  Serving cell at export time:")
        appendLine("    technology      : ${snapshot.rat}")
        appendLine("    bandwidth       : ${snapshot.bandwidthKhz?.let { "$it kHz" } ?: "not reported"}")
        appendLine("    channel (earfcn): ${snapshot.earfcn ?: "not reported"}")
        appendLine("    neighbour cells : ${snapshot.neighborCount}")
        appendLine("    serving RSRP    : ${snapshot.servingRsrp?.let { "$it dBm" } ?: "not reported"}")
        appendLine("    TAC changes (5m): ${snapshot.tacChangesLast5m}")
        appendLine("    TAC changed     : ${snapshot.tacChanged}")
        appendLine("    RAT changed     : ${snapshot.ratChanged}")
        appendLine("    moved (5m)      : ${snapshot.locationMovedMLast5m?.let { "$it m" } ?: "unknown"}" +
            (snapshot.locationFixAgeS?.let { " (fix ${it}s old)" } ?: ""))
        appendLine("    screen on       : ${snapshot.capture.screenInteractive ?: "unknown"}")
        appendLine("    records in read : ${snapshot.capture.rawRecordCount}")
        appendLine("    PLMN = SIM      : ${snapshot.sim.plmnMatchesSim ?: "unknown"}")
        appendLine("    name = SIM      : ${snapshot.sim.operatorNameMatchesSim ?: "unknown"}")
        appendLine("  ${CellularRedaction.REDACTION_NOTE}")
        appendLine()
        appendCellularObservations(history)
    }

    /**
     * Every retained observation, not just the last one.
     *
     * The monitor held 46 snapshots in memory while the report printed one:
     * the export read `latest` and never `history`. A single end-state cannot
     * show a radio's behaviour over a session — whether neighbours came and
     * went, when the RAT moved, how RSRP tracked — and that time series is
     * the actual Tier 1 evidence. Oldest first so it reads as a timeline.
     *
     * Same redaction as everything else that leaves the device: condition,
     * never tower identity.
     */
    private fun StringBuilder.appendCellularObservations(history: List<CellularSnapshot>) {
        if (history.isEmpty()) return
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        val retained = if (history.size >= CellularState.MAX_HISTORY) {
            " (most recent ${CellularState.MAX_HISTORY} retained)"
        } else {
            ""
        }
        appendLine("  Observations this session, oldest first: ${history.size}$retained")
        history.asReversed().forEach { s ->
            appendLine("    [${fmt.format(Date(s.capturedAt))}] ${cellularObservationLine(s)}")
        }
        appendLine()
    }

    /** One observation as `key=value` pairs. Exportable keys only — see [CellularRedaction]. */
    private fun cellularObservationLine(s: CellularSnapshot): String = buildString {
        append("rat=").append(s.rat)
        append(" earfcn=").append(s.earfcn ?: "-")
        append(" bands=").append(s.bands.joinToString(",").ifEmpty { "-" })
        append(" bw=").append(s.bandwidthKhz ?: "-")
        append(" neighbours=").append(s.neighborCount)
        append(" rsrp=").append(s.servingRsrp ?: "-")
        append(" tacChanged=").append(s.tacChanged)
        append(" ratChanged=").append(s.ratChanged)
        append(" churn5m=").append(s.tacChangesLast5m)
        append(" moved5m=").append(s.locationMovedMLast5m ?: "-")
        append(" fixAge=").append(s.locationFixAgeS ?: "-")
        append(" origin=").append(s.capture.origin.name)
        append(" records=").append(s.capture.rawRecordCount)
        append(" screen=").append(s.capture.screenInteractive ?: "-")
        append(" fg=").append(s.capture.appForeground ?: "-")
        append(" data=").append(s.capture.dataActivity ?: "-")
        append(" simPlmn=").append(s.sim.plmnMatchesSim ?: "-")
        append(" simName=").append(s.sim.operatorNameMatchesSim ?: "-")
    }

    /**
     * Tier 1 cellular findings.
     *
     * These come from the forensic timeline rather than [ScanResult.findings]:
     * the radio emitter is event-driven and continuous, so a finding is not
     * produced by any particular scan. Each row carries the full radio context
     * it fired on, because a cellular finding cannot be judged true or false
     * after the fact without the snapshot that produced it.
     */
    internal fun StringBuilder.appendCellularSection(events: List<ForensicTimelineEvent>) {
        if (events.isEmpty()) return
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        section("CELLULAR (TIER 1)")
        appendLine("  ${events.size} finding(s) from radio telemetry.")
        appendLine()
        events.forEach { e ->
            appendLine("  [${fmt.format(Date(e.startTimestamp))}] ${e.description}")
            if (e.ruleId.isNotEmpty()) appendLine("    rule: ${e.ruleId}")
            if (e.attackTechniqueId.isNotEmpty()) {
                appendLine("    technique: ${e.attackTechniqueId}")
            }
            // Redacted: a report is a handoff artifact and must not carry a
            // tower-level location trail. Full context stays on-device.
            if (e.details.isNotEmpty()) {
                appendLine("    context: ${CellularRedaction.redact(e.details)}")
            }
            appendLine()
        }
    }
}
