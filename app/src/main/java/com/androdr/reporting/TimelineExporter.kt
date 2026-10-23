package com.androdr.reporting

import android.os.Build
import com.androdr.data.model.CivilDay
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.effectiveCorrelationId
import com.androdr.data.model.effectivePackageFromDescription
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Exports Timeline events as plaintext or CSV, streaming: callers hand rows over page by page
 * ([PlaintextWriter], [writeCsvHeader] / [writeCsvRow]) and nothing holds the whole Timeline
 * (spec §7). Device-controlled text goes through [escapeForReport] (no raw line break or bidi
 * override reaches the file) and CSV cells keep the formula-injection guard. The fixed text is ASCII.
 */
object TimelineExporter {

    private const val RULE = "============================================================"
    private const val THIN = "------------------------------------------------------------"

    // Column set mirrors the on-screen Timeline detail sheet plus the clustering/correlation fields
    // the UI uses to render cluster cards and the Linked Evidence section. Without rule_id +
    // correlation_id + kind, a CSV consumer can't tell whether a row is a raw event or a correlation
    // signal, which rule produced it, or which other rows share its cluster. record_id is the stored
    // fact an event is (or a finding row points at): the id a `1:<id>` member ref names.
    const val CSV_HEADER = "timestamp,isodate,end_timestamp,end_isodate,kind,module,event,data,package," +
        "severity,rule_id,correlation_id,member_refs,scan_result_id," +
        "ioc_indicator,ioc_type,ioc_source,campaign,mitre_technique,apk_hash,details,record_id,time_precision"

    /** `timestampPrecision` of a day-precision event: written date-only, never with a time of day (R31). */
    const val DAY_PRECISION = "day"

    /**
     * What the plaintext header summarises, gathered in a first streaming pass over the rows
     * ([add]); the package set is bounded by the apps on the device.
     */
    class PlaintextStats(private val ruleGuidance: Map<String, String>) {
        var total = 0L
            private set
        private var significant = 0L
        private var maxGuidancePriority = 0
        private val packages = HashSet<String>()

        fun add(event: ForensicTimelineEvent) {
            total++
            if (event.packageName.isNotEmpty()) packages += event.packageName
            val guidance = ruleGuidance[event.ruleId]
            if (event.ruleId.isNotEmpty() && !guidance.isNullOrEmpty()) {
                // Significant == events whose rule guidance is non-empty. Rule guidance is present
                // only on rules that produce findings, so this counts rows tied to a rule.
                significant++
                maxGuidancePriority = maxOf(maxGuidancePriority, GuidanceUtils.guidancePriority(guidance))
            }
        }

        /** Assessment derived from rule guidance: the rules define threat severity. */
        internal val assessment: String
            get() = when {
                maxGuidancePriority >= CRITICAL_PRIORITY -> "CRITICAL ACTIVITY DETECTED"
                maxGuidancePriority >= 1 || significant > 0 -> "REVIEW RECOMMENDED"
                else -> "NO CONCERNS"
            }

        internal val significantCount: Long get() = significant
        internal val packageCount: Int get() = packages.size
    }

    /**
     * Writes the plaintext report to [out]: [header] once (with the first pass's [PlaintextStats]),
     * then each row through [event] in display order (newest first), then [footer].
     * [displayName] resolves a package's app name when the row carries none.
     */
    class PlaintextWriter(
        private val out: Appendable,
        private val displayName: (String) -> String? = { null },
    ) {
        private val dateFmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)
        private var currentDate = ""
        private var empty = true

        /** [filter]: the active Timeline filter in words, or null for the whole Timeline. */
        fun header(stats: PlaintextStats, versionName: String, filter: String? = null) {
            out.line(RULE)
            out.line("  AndroDR Forensic Timeline")
            out.line("  Version: ${escapeForReport(versionName)}")
            out.line("  Generated: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
            out.line("  Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
            out.line("  Device: ${Build.MANUFACTURER} ${Build.MODEL}")
            out.line("  Patch: ${Build.VERSION.SECURITY_PATCH}")
            out.line("  Events: ${stats.total}")
            if (filter != null) out.line("  Filtered: ${escapeForReport(filter)}")
            out.line(RULE)
            out.line("")
            empty = stats.total == 0L
            if (empty) {
                out.line("  No timeline events recorded.")
                out.line("")
                return
            }
            out.line("  Total events: ${stats.total}")
            out.line("")
            out.line("  ASSESSMENT: ${stats.assessment}")
            if (stats.significantCount > 0) {
                out.line("  ${stats.significantCount} event(s) across ${stats.packageCount} package(s) " +
                    "require attention.")
            }
            out.line("")
        }

        fun event(event: ForensicTimelineEvent) {
            val date = dateOf(event)
            if (date != currentDate) {
                currentDate = date
                out.line(THIN)
                out.line("  $date")
                out.line(THIN)
            }
            out.line("  ${timeOf(event)}  ${escapeForReport(event.description)}")
            val pkg = escapeForReport(event.packageName)
            if (event.appName.isNotEmpty() && event.appName != event.packageName) {
                out.line("             App: ${escapeForReport(event.appName)} ($pkg)")
            } else if (event.packageName.isNotEmpty()) {
                val resolved = displayName(event.packageName)
                if (resolved != null) {
                    out.line("             App: ${escapeForReport(resolved)} ($pkg)")
                } else {
                    out.line("             Package: $pkg")
                }
            }
            if (event.iocIndicator.isNotEmpty()) {
                out.line("             IOC: ${escapeForReport(event.iocIndicator)} (${escapeForReport(event.iocType)})")
            }
            if (event.campaignName.isNotEmpty()) {
                out.line("             Campaign: ${escapeForReport(event.campaignName)}")
            }
            if (event.apkHash.isNotEmpty()) out.line("             APK SHA-256: ${escapeForReport(event.apkHash)}")
            if (event.details.isNotEmpty()) out.line("             ${escapeForReport(event.details)}")
        }

        /**
         * A row's nested evidence, right after the row and inside the row's date section (it never
         * opens a section of its own, so a cross-day evidence fact cannot repeat a date header).
         */
        fun evidence(event: ForensicTimelineEvent) {
            out.line("             Evidence: ${dateOf(event)} ${timeOf(event)}  ${escapeForReport(event.description)}")
        }

        /** The date section an entry falls in: a day-precision date in UTC (R32), an instant on this device. */
        private fun dateOf(event: ForensicTimelineEvent): String = when {
            event.startTimestamp <= 0 -> "Unknown"
            event.timestampPrecision == DAY_PRECISION -> CivilDay.format(event.startTimestamp)
            else -> dateFmt.format(Date(event.startTimestamp))
        }

        private fun timeOf(event: ForensicTimelineEvent): String = when {
            event.timestampPrecision == DAY_PRECISION -> "(date only)"
            event.startTimestamp > 0 -> timeFmt.format(Date(event.startTimestamp))
            else -> "??:??:??"
        }

        fun footer() {
            if (empty) {
                out.line(RULE)
                return
            }
            out.line("")
            out.line(RULE)
            out.line("  End of timeline / AndroDR")
            out.line(RULE)
        }
    }

    /** The whole plaintext report of [events] in memory: small lists only (tests, previews). */
    fun formatPlaintext(
        events: List<ForensicTimelineEvent>,
        displayNames: Map<String, String> = emptyMap(),
        ruleGuidance: Map<String, String> = emptyMap(),
        versionName: String
    ): String = buildString {
        val stats = PlaintextStats(ruleGuidance).apply { events.forEach(::add) }
        val writer = PlaintextWriter(this, displayNames::get)
        writer.header(stats, versionName)
        events.sortedByDescending { it.startTimestamp }.forEach(writer::event)
        writer.footer()
    }

    fun writeCsvHeader(out: Appendable) {
        out.line(CSV_HEADER)
    }

    /**
     * One CSV row. [memberRefs]: a signal row's members that still exist, as `kind:id` (`0` a
     * timeline row, `1` a stored fact), from `signal_member` — the only store of member lists (spec §5.4).
     */
    fun writeCsvRow(out: Appendable, event: ForensicTimelineEvent, memberRefs: List<String> = emptyList()) {
        val iso = when {
            event.startTimestamp <= 0 -> ""
            event.timestampPrecision == DAY_PRECISION -> date(event.startTimestamp)
            else -> utc(event.startTimestamp)
        }
        val endIso = event.endTimestamp?.let { if (it > 0) utc(it) else "" } ?: ""
        // Fall back to the description-parsed package so legacy rows are not blank in the export.
        val pkg = event.packageName.takeIf { it.isNotBlank() } ?: event.effectivePackageFromDescription().orEmpty()
        // Severity column kept in the header for backward compatibility with consumers; always empty
        // (severity lives on findings). The correlation id falls back to the read-time key the
        // Timeline UI uses (it also parses legacy rows whose description starts with a package).
        val cells = listOf(
            event.startTimestamp.toString(), iso, event.endTimestamp?.toString().orEmpty(), endIso,
            csvEscape(event.kind), csvEscape(event.source), csvEscape(event.category), csvEscape(event.description),
            csvEscape(pkg), "", csvEscape(event.ruleId), csvEscape(event.effectiveCorrelationId()),
            csvEscape(memberRefs.joinToString(";")), event.scanResultId.toString(), csvEscape(event.iocIndicator),
            csvEscape(event.iocType), csvEscape(event.iocSource), csvEscape(event.campaignName),
            csvEscape(event.attackTechniqueId), csvEscape(event.apkHash), csvEscape(event.details),
            event.recordId?.toString().orEmpty(), csvEscape(event.timestampPrecision),
        )
        out.line(cells.joinToString(","))
    }

    /** The whole CSV of [events] in memory, oldest first: small lists only (tests). */
    fun formatCsv(events: List<ForensicTimelineEvent>, memberRefs: Map<Long, List<String>> = emptyMap()): String =
        buildString {
            writeCsvHeader(this)
            for (event in events.sortedBy { it.startTimestamp }) {
                writeCsvRow(this, event, memberRefs[event.id].orEmpty())
            }
        }

    private const val CRITICAL_PRIORITY = 3

    private val utcFormat: ThreadLocal<SimpleDateFormat> = ThreadLocal.withInitial {
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }
    }

    private fun utc(ms: Long): String = utcFormat.get()!!.format(Date(ms))

    /**
     * A day-precision time as its calendar date. It is stored as that date's UTC midnight (ruling
     * R32), so it is read in UTC: the date the source printed, whatever this device's zone.
     */
    private fun date(ms: Long): String = CivilDay.format(ms)

    private fun Appendable.line(text: String) {
        append(text).append('\n')
    }

    private fun csvEscape(raw: String): String {
        val value = escapeForReport(raw)
        // Prevent CSV formula injection (cells starting with =, +, -, @, \t, \r)
        val sanitized = if (value.isNotEmpty() && value[0] in setOf('=', '+', '-', '@', '\t', '\r')) {
            "'" + value
        } else value
        return if (sanitized.contains(',') || sanitized.contains('"') || sanitized.contains('\n')) {
            "\"${sanitized.replace("\"", "\"\"")}\""
        } else sanitized
    }
}
