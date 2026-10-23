package com.androdr.scanner

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TimelineEvent
import com.androdr.data.model.UsageEvent
import com.androdr.data.repo.Correlation
import com.androdr.data.repo.FindingTotals
import com.androdr.data.repo.SessionHooks
import com.androdr.data.repo.TimelineRowDeleter
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.IntrusionLogRecordBuilders
import com.androdr.sigma.LiveRecordBuilders
import com.androdr.sigma.RuleCoverage
import com.androdr.sigma.SigmaCorrelationEngine
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.StoreRecord
import java.util.Collections

/**
 * What every writer adds to its session's finishing transaction in Phases A–C (spec §5.2): the
 * interim event rows ([interim], fed per chunk), the writer's detected-change or module rows
 * ([extraRows]), and the correlation pass over this scan's just-written rows — with [lookback]
 * rows for a live scan — whose chain coverage gaps (#370) land on the summary.
 */
internal abstract class WriterHooks(
    protected val scan: ScanResult,
    private val engine: SigmaRuleEngine,
    private val correlationEngine: SigmaCorrelationEngine,
) : SessionHooks {
    val interim = InterimTimelineRows()

    /** Non-fatal problems the writer met; they land on the completed scan's `scannerErrors`. */
    val errors: MutableList<ScannerFailure> = Collections.synchronizedList(mutableListOf())

    // Only enabled rules contribute to correlation category propagation (and to the severity of
    // the findings the chains become, #350): a disabled rule's category must not influence
    // classifications when it produces no bindings.
    private val rules = engine.getCorrelationRules()
    private val atomRulesById = engine.getEnabledRules().associateBy { it.id }
    private var chainSkips: List<ScannerFailure> = emptyList()

    /** The session's finding totals, once [summarize] ran (counts past the intrusion-log cap). */
    var totals: FindingTotals? = null
        private set

    /** Rows already in the database that take part in this scan's correlation (live scans only). */
    protected open suspend fun lookback(): List<ForensicTimelineEvent> = emptyList()

    /** Rows written before the interim rows (detected changes, bug-report module rows). */
    protected open fun extraRows(scan: ScanResult): List<ForensicTimelineEvent> = emptyList()

    override fun onChunk(
        service: String, source: TelemetrySource, chunk: List<StoreRecord>, firstOrdinal: Int,
        factIds: LongArray?, observed: BooleanArray?,
    ) = interim.onChunk(service, factIds, observed)

    override fun interimRows(scan: ScanResult): List<ForensicTimelineEvent> =
        extraRows(scan) + interim.rows(scan.id)

    override suspend fun correlate(rows: List<ForensicTimelineEvent>): Correlation {
        val events = lookback() + rows
        // #370: a chain rule fires only where every leg has events to bind to; legs with nothing
        // recorded are declared, so "no warning signs" never stands in for "not checked".
        chainSkips = RuleCoverage.noEventSkipsFor(rules, engine.atomCategories(), events)
        if (rules.isEmpty() || events.isEmpty()) return Correlation.NONE
        val bindings = engine.computeAtomBindings(events)
        val signals = correlationEngine.evaluate(rules, events, bindings, atomRulesById)
            .map { it.copy(scanResultId = scan.id) }
        if (signals.isEmpty()) return Correlation.NONE
        return Correlation(signals, correlationEngine.findingsFor(signals, rules, atomRulesById))
    }

    override fun summarize(scan: ScanResult, totals: FindingTotals): ScanResult {
        this.totals = totals
        return scan.copy(
            knownMalwareCount = totals.knownMalware,
            scannerErrors = scan.scannerErrors + synchronized(errors) { errors.toList() } + chainSkips,
        )
    }

    /** [row] with the APK hash of its package from [hashByPkg] when the finding carried none. */
    protected fun withApkHash(row: ForensicTimelineEvent, hashByPkg: Map<String, String>): ForensicTimelineEvent =
        if (row.apkHash.isEmpty() && row.packageName.isNotEmpty()) {
            row.copy(apkHash = hashByPkg[row.packageName] ?: "")
        } else {
            row
        }
}

/**
 * The live scan: finding rows enriched with APK hashes, the detected-change rows (first-seen
 * installs, device-admin grants), the `usage_stats` rows of the re-read usage window replaced, a
 * correlation lookback read before the session writes ([readLookback]) that excludes imported
 * intrusion-log rows (#342 B2), and the event watermarks this scan advances (spec §5.2).
 */
@Suppress("LongParameterList") // the live scan's inputs, built once by ScanOrchestrator
internal class LiveScanHooks(
    scan: ScanResult,
    engine: SigmaRuleEngine,
    correlationEngine: SigmaCorrelationEngine,
    private val timeline: ForensicTimelineEventDao,
    private val timelineRows: TimelineRowDeleter,
    private val hashByPkg: Map<String, String>,
    private val detectedChanges: List<ForensicTimelineEvent>,
    private val lookbackWindowMs: Long,
    private val usage: UsageWindow,
    private val dns: DnsWindow,
    private val clock: () -> Long = System::currentTimeMillis,
) : WriterHooks(scan, engine, correlationEngine) {
    init {
        interim.register<UsageEvent>(
            USAGE_STATS, cap = null, keepUnobserved = true, time = { it.timestamp },
        ) { e, scanId -> e.toForensicTimelineEvent(scanId) }
    }

    /** The DNS id this scan collected through; set once every row of [DnsWindow.range] was appended. */
    var dnsCollectedThrough: Long? = null

    /** A DNS read failed mid-stream: the DNS watermark stays put. */
    var dnsReadFailed = false

    /**
     * Whether this scan's usage rows replace earlier ones: only when usage was collected, and only
     * inside the re-read window `[since, until]`, where it writes a row for every event it read.
     * Rows outside it are kept: this scan cannot read their events. That includes rows stamped
     * after `until`, which exist when the device clock moved back since they were written.
     */
    private val replacesUsage = usage.collection is UsageCollection.Ok

    private fun replacedUsageRow(row: ForensicTimelineEvent): Boolean =
        replacesUsage && row.source == USAGE_STATS && row.startTimestamp in usage.since..usage.until

    override suspend fun sweepPrior(scanId: Long) {
        if (replacesUsage) timelineRows.bySourceBetween(USAGE_STATS, usage.since, usage.until)
    }

    override fun watermarks(saveFallback: Boolean): Map<String, Long> = buildMap {
        Watermarks.nextTime(usage.previous, usage.collection, usage.until, clock(), saveFallback)
            ?.let { put(USAGE_STATS, it) }
        Watermarks.nextDnsId(dns.previous, dnsCollectedThrough, dns.failed || dnsReadFailed, saveFallback)
            ?.let { put(LiveRecordBuilders.DNS_MONITOR, it) }
    }

    override fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent =
        withApkHash(finding.toForensicTimelineEvent(scan), hashByPkg)

    override fun extraRows(scan: ScanResult): List<ForensicTimelineEvent> = detectedChanges

    private var lookbackRows: List<ForensicTimelineEvent> = emptyList()

    /**
     * Reads the correlation lookback BEFORE the session writes anything, so `finish`'s correlation
     * never sees this scan's own rows twice (spec §5.2: an event is counted once). The window ends
     * at the scan start; rows of this scan and the `usage_stats` rows `finish` replaces (those of the
     * re-read window: this scan writes their events again) are left out.
     *
     * #342 B2: imported intrusion-log rows carry their own historical event time, so a plain
     * time-window query would sweep them in, and any signal they helped produce would be stamped
     * with this live scan's id — unreachable by the intrusion-log sweep (an orphan signal).
     */
    suspend fun readLookback() {
        if (lookbackWindowMs <= 0L) return
        lookbackRows = runCatching {
            timeline.getEventsSinceExcludingTelemetrySource(
                scan.timestamp - lookbackWindowMs, TelemetrySource.INTRUSION_LOG_IMPORT
            )
        }.getOrDefault(emptyList()).filter {
            it.startTimestamp <= scan.timestamp && it.scanResultId != scan.id && !replacedUsageRow(it)
        }
    }

    override suspend fun lookback(): List<ForensicTimelineEvent> = lookbackRows

    override fun summarize(scan: ScanResult, totals: FindingTotals): ScanResult = super.summarize(scan, totals).copy(
        riskySideloadCount = scan.findings.count {
            it.category == FindingCategory.APP_RISK && it.matchContext["is_sideloaded"] == "true"
        },
    )

    companion object {
        const val USAGE_STATS = "usage_stats"
    }
}

/**
 * An intrusion-log import: finding rows stamped with the import's source and their record's own
 * time, the capped newest-first DNS / connect / security rows (#342 B3/B4), and the
 * replace-on-reimport sweep of every prior import ([deletePriorIntrusionLogRows]).
 */
internal class IntrusionLogHooks(
    scan: ScanResult,
    engine: SigmaRuleEngine,
    correlationEngine: SigmaCorrelationEngine,
    private val timeline: ForensicTimelineEventDao,
    private val timelineRows: TimelineRowDeleter,
) : WriterHooks(scan, engine, correlationEngine) {
    init {
        interim.register<ImportedDnsEvent>(
            IntrusionLogRecordBuilders.DNS_MONITOR, ScanOrchestrator.DNS_PERSIST_CAP, keepUnobserved = false,
            time = { it.event.timestamp },
        ) { e, scanId -> e.toForensicTimelineEvent(scanId) }
        interim.register<NetworkTelemetry>(
            IntrusionLogRecordBuilders.NETWORK_MONITOR, ScanOrchestrator.CONNECT_PERSIST_CAP, keepUnobserved = false,
            time = { it.timestamp },
        ) { e, scanId -> e.toForensicTimelineEvent(scanId) }
        interim.register<SecurityLogEvent>(
            IntrusionLogRecordBuilders.SECURITY_LOG, ScanOrchestrator.SECURITY_PERSIST_CAP, keepUnobserved = false,
            time = { it.timestamp },
        ) { e, scanId -> e.toForensicTimelineEvent(scanId) }
    }

    override suspend fun sweepPrior(scanId: Long) = deletePriorIntrusionLogRows(scanId)

    override fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent =
        finding.toForensicTimelineEvent(scan, isBugreport = true).copy(
            source = "intrusion_log_analysis",
            telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT,
            // The DNS/network/security field maps carry "timestamp" and the evaluator copies scalar
            // record fields into matchContext as strings, so a finding inherits its own event's
            // time. A finding without one falls back to 0L, which the Timeline renders as "Unknown".
            startTimestamp = FindingRank.eventTimeMs(finding)
        )

    /**
     * Replace-on-reimport sweep (#342 spec §4.2; Phases A–C, forensic rows only): removes every
     * Timeline row a previous intrusion-log import left behind, as the first statement of the
     * finishing transaction, so a failed finish rolls it back. [currentScanId] is excluded.
     *
     * Deleting by source alone is not enough. The correlation engine persists its signals with
     * `source = "sigma_correlation_engine"` (shared with the live-scan and bug-report paths, so that
     * source must never be deleted wholesale) and each signal's `member_event_ids` points at the
     * raw rows that produced it. Every row of one import — raw, finding, and signal — carries that
     * import's `scanResultId`, so the ids owning "intrusion_log" rows identify the whole set. The
     * two source deletes still run afterwards as belt-and-braces for rows written without a scan id.
     * The prior imports' facts and observations stay in the store until their scans are deleted.
     */
    private suspend fun deletePriorIntrusionLogRows(currentScanId: Long) {
        timeline.getDistinctScanIdsBySource("intrusion_log").filter { it != currentScanId }.forEach { priorScanId ->
            timelineRows.byScanId(priorScanId)
        }
        timelineRows.bySource("intrusion_log")
        timelineRows.bySource("intrusion_log_analysis")
    }
}

/**
 * A bug-report import: finding rows enriched with APK hashes, then the modules' raw timeline rows
 * not already covered by a finding row at the same (package, time) — so a finding and its raw
 * evidence don't read as duplicates — and the modules' own rows (e.g. install times).
 */
internal class BugReportHooks(
    scan: ScanResult,
    engine: SigmaRuleEngine,
    correlationEngine: SigmaCorrelationEngine,
    private val hashByPkg: Map<String, String>,
    private val moduleTimeline: List<TimelineEvent>,
    private val moduleRows: List<ForensicTimelineEvent>,
) : WriterHooks(scan, engine, correlationEngine) {
    private val coveredByFinding = HashSet<Pair<String, Long>>()

    override fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent {
        val row = withApkHash(finding.toForensicTimelineEvent(scan, isBugreport = true), hashByPkg)
        if (row.startTimestamp > 0L && row.packageName.isNotEmpty()) {
            coveredByFinding += row.packageName to row.startTimestamp
        }
        return row
    }

    /** Called after every [findingRow] of the finishing transaction. */
    override fun extraRows(scan: ScanResult): List<ForensicTimelineEvent> =
        moduleTimeline
            .filterNot { raw -> raw.packageName != null && (raw.packageName to raw.timestamp) in coveredByFinding }
            .map { it.toForensicTimelineEvent(scan.id) } +
            moduleRows.map { it.copy(scanResultId = scan.id) }
}

/**
 * Appends each intrusion-log chunk to the writer [session], staging its typed records in [interim]
 * first so the session's `onChunk` can pair them with their fact ids.
 */
internal class IntrusionLogSessionChunks(
    private val session: ChunkedScanWriter.Session,
    private val interim: InterimTimelineRows,
    private val fallbackCapturedAt: Long,
) : IntrusionLogChunks {
    override suspend fun dns(events: List<ImportedDnsEvent>, records: List<StoreRecord>) =
        put(IntrusionLogRecordBuilders.DNS_MONITOR, events, records)

    override suspend fun connect(events: List<NetworkTelemetry>, records: List<StoreRecord>) =
        put(IntrusionLogRecordBuilders.NETWORK_MONITOR, events, records)

    override suspend fun security(events: List<SecurityLogEvent>, records: List<StoreRecord>) =
        put(IntrusionLogRecordBuilders.SECURITY_LOG, events, records)

    private suspend fun <T> put(service: String, events: List<T>, records: List<StoreRecord>) {
        interim.stage(service, events)
        val capturedAt = capturedAtOf(records, fallbackCapturedAt)
        session.append(service, TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt, records)
    }
}

/**
 * The `captured_at` the records of one append share (their first record's), so the store strips it
 * from their bodies; [fallback] when the records carry none.
 */
internal fun capturedAtOf(records: List<StoreRecord>, fallback: Long): Long =
    (records.firstOrNull()?.fields?.get("captured_at") as? Long) ?: fallback
