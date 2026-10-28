package com.androdr.data.repo

import com.androdr.data.db.AuditGroup
import com.androdr.data.db.AuditJsonRow
import com.androdr.data.db.Converters
import com.androdr.data.db.ScanFindingDao
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The persistent audit row a scan deletion or "Clear all" writes in its first transaction (spec §5.4):
 * the deleted triggered findings as distinct (rule, level, package) entries with counts, at most
 * [MAX_ENTRIES] entries plus "and K more", so the row stays small whatever the scan's size.
 *
 * Bounded memory: the entries of findings that carry Timeline columns come from SQL `GROUP BY … LIMIT`
 * ([ScanFindingDao.auditGroups]); findings without them (migrated from schema 20, and correlation
 * findings) store their package only in `findingJson`, so they are read in keyset pages and folded
 * into at most [MAX_JSON_KEYS] entries (the rest count toward "and K more"). The text is also cut at
 * [MAX_DETAIL_BYTES], so the row stays under 16 KB.
 */
internal class DeletionAudit(private val dao: ScanFindingDao) {

    /** The audit row for deleting [scan] (read while it is still COMPLETE). */
    suspend fun forScan(scan: ScanResult, now: Long): ForensicTimelineEvent {
        val details = details(
            dao.auditGroups(scan.id, MAX_ENTRIES), dao.triggeredTotal(scan.id),
            "deleted with this scan",
        ) { after, size -> dao.auditJsonRows(scan.id, after, size) }
        val what = when (scan.source) {
            TelemetrySource.LIVE_SCAN -> "Scan"
            TelemetrySource.BUGREPORT_IMPORT -> "Bug report import"
            TelemetrySource.INTRUSION_LOG_IMPORT -> "Intrusion log import"
        }
        return row(now, "$what of ${format(scan.timestamp)} deleted", details, scan.source)
    }

    /**
     * The single audit row for "Clear all" over every COMPLETE scan ([scans] of them), noting the
     * [interrupted] scans (killed writers) it removes too (review m11).
     */
    suspend fun forAll(scans: Int, interrupted: Int, now: Long): ForensicTimelineEvent {
        val details = details(dao.auditGroupsAll(MAX_ENTRIES), dao.triggeredTotalAll(), "deleted by Clear all") {
                after, size -> dao.auditJsonRowsAll(after, size)
        }
        val extra = if (interrupted > 0) " and $interrupted interrupted scan(s)" else ""
        return row(now, "All scan history cleared ($scans scan(s)$extra)", details, TelemetrySource.LIVE_SCAN)
    }

    private fun row(now: Long, description: String, details: String, source: TelemetrySource) = ForensicTimelineEvent(
        startTimestamp = now, source = SOURCE, category = CATEGORY, description = description, details = details,
        telemetrySource = source, scanResultId = -1L, createdAt = now, persistent = true,
    )

    private suspend fun details(
        sqlGroups: List<AuditGroup>, total: Long, verb: String,
        jsonPage: suspend (Long, Int) -> List<AuditJsonRow>,
    ): String {
        val counts = LinkedHashMap<Triple<String, String, String>, Long>()
        for (g in sqlGroups) counts.merge(Triple(g.ruleId, g.level, g.packageName), g.count.toLong(), Long::plus)
        var jsonKeys = 0
        var after = 0L
        while (true) {
            val page = jsonPage(after, JSON_PAGE)
            for (r in page) {
                val key = Triple(r.ruleId, r.level, packageOf(r.findingJson))
                if (key in counts || jsonKeys < MAX_JSON_KEYS) {
                    if (key !in counts) jsonKeys++
                    counts.merge(key, 1L, Long::plus)
                }
            }
            if (page.size < JSON_PAGE) break
            after = page.last().id
        }
        val sb = StringBuilder()
        sb.append("$total triggered finding(s) $verb. Alerts and their evidence are kept.")
        if (total == 0L) return sb.append("\nNo triggered findings.").toString()
        var shownEntries = 0
        var shownFindings = 0L
        var bytes = utf8Length(sb)
        val sorted = counts.entries.sortedWith(
            compareByDescending<Map.Entry<Triple<String, String, String>, Long>> { it.value }
                .thenBy { it.key.first }.thenBy { it.key.second }.thenBy { it.key.third }
        )
        for ((key, n) in sorted.take(MAX_ENTRIES)) {
            val line = "\n${key.first.take(MAX_RULE)} · ${key.second.take(MAX_LEVEL)} · " +
                "${key.third.ifEmpty { "—" }.take(MAX_PACKAGE)} × $n"
            val lineBytes = utf8Length(line)
            if (bytes + lineBytes > MAX_DETAIL_BYTES) break
            sb.append(line)
            bytes += lineBytes
            shownEntries++
            shownFindings += n
        }
        val more = total - shownFindings
        if (more > 0) sb.append("\n…and $more more finding(s)")
        return sb.toString()
    }

    private fun packageOf(json: String): String {
        val ctx = Converters.decodeFinding(json)?.matchContext ?: return ""
        return ctx["package_name"] ?: ctx["source_package"] ?: ""
    }

    private fun utf8Length(s: CharSequence): Int = s.toString().toByteArray(Charsets.UTF_8).size

    private fun format(ts: Long): String = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(ts))

    companion object {
        const val SOURCE = "androdr_store"
        const val CATEGORY = "scan_deleted"

        /** Entries listed before "and K more" (spec §5.4). */
        const val MAX_ENTRIES = 100
        private const val MAX_JSON_KEYS = 1_000
        private const val JSON_PAGE = 500
        private const val MAX_DETAIL_BYTES = 12_000
        private const val MAX_RULE = 64
        private const val MAX_LEVEL = 16
        private const val MAX_PACKAGE = 128
    }
}
