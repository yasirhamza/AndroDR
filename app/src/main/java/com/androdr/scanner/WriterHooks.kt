package com.androdr.scanner

import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.Correlation
import com.androdr.data.repo.FindingTotals
import com.androdr.data.repo.SessionHooks
import com.androdr.data.store.AtomReader
import com.androdr.sigma.CorrelationBudget
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.IntrusionLogRecordBuilders
import com.androdr.sigma.LiveRecordBuilders
import com.androdr.sigma.NotStartedCause
import com.androdr.sigma.RuleCoverage
import com.androdr.sigma.SigmaCorrelationEngine
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.StoreRecord
import com.androdr.sigma.TimelineAtom
import java.util.Collections

/** The correlation budget's clock: monotonic milliseconds (a wall-clock jump never cuts a pass short). */
internal fun monotonicMs(): Long = System.nanoTime() / NANOS_PER_MS

private const val NANOS_PER_MS = 1_000_000L

/**
 * What every writer adds to its session's finishing transaction (spec §5.2): its finding rows, the
 * live scan's detected-change rows ([extraRows]), and the correlation pass over this scan's atoms —
 * read after its rows were written, plus [lookbackAtoms] for a live scan — under a
 * [CorrelationBudget] ([newBudget]). Event records are never rows (C3): they are facts in the store,
 * and correlation reads them there. Chain coverage gaps (#370) and budget cut-offs land on the
 * summary.
 */
internal abstract class WriterHooks(
    protected val scan: ScanResult,
    private val engine: SigmaRuleEngine,
    private val correlationEngine: SigmaCorrelationEngine,
    private val newBudget: () -> CorrelationBudget = { CorrelationBudget(::monotonicMs) },
) : SessionHooks {
    /** Non-fatal problems the writer met; they land on the completed scan's `scannerErrors`. */
    val errors: MutableList<ScannerFailure> = Collections.synchronizedList(mutableListOf())

    // Only enabled rules contribute to correlation category propagation (and to the severity of
    // the findings the chains become, #350): a disabled rule's category must not influence
    // classifications when it produces no bindings.
    private val rules = engine.getCorrelationRules()
    private val atomRulesById = engine.getEnabledRules().associateBy { it.id }
    private var chainSkips: List<ScannerFailure> = emptyList()
    private var incompleteSkips: List<ScannerFailure> = emptyList()

    /** The session's finding totals, once [summarize] ran (counts past the intrusion-log cap). */
    var totals: FindingTotals? = null
        private set

    /**
     * Atoms already in the database that take part in this scan's correlation (live scans only).
     * An import correlates over its own atoms only, so its signals never reference live data.
     */
    protected open suspend fun lookbackAtoms(atoms: AtomReader, categories: Set<String>): List<TimelineAtom> =
        emptyList()

    /**
     * Inside the finishing transaction, after this scan's rows were inserted: this scan's own atoms
     * (its rows with their real ids, and the facts it observed) plus [lookbackAtoms], each ref once.
     * The budget's total deadline covers the reads, binding and grouping; a cut-off returns normally
     * with the signals already found and a CORRELATION_INCOMPLETE entry per affected rule.
     */
    override suspend fun correlate(scan: ScanResult, atoms: AtomReader): Correlation {
        val budget = newBudget()
        val atomCategoryByRuleId = engine.atomCategories()
        val categories = atomCategoryByRuleId.values.toSet()
        // Review m-2 / I-3: the one foreseeable, deterministic reason the atoms cannot be read is a
        // rule set binding more categories than one query holds. Checked before any read, and said
        // as such; every other read failure propagates and fails the finish honestly (a swallowed
        // SQLite error could leave a half-written scan marked COMPLETE).
        if (categories.size > AtomReader.MAX_ATOM_CATEGORIES) {
            incompleteSkips = correlationEngine.notStarted(rules, NotStartedCause.TOO_MANY_CATEGORIES)
            return Correlation.NONE
        }
        val all = (atoms.atomsForScan(scan.id, categories) + lookbackAtoms(atoms, categories)).distinctBy { it.ref }
        // #370: a chain rule fires only where every leg has events to bind to; legs with nothing
        // recorded are declared, so "no warning signs" never stands in for "not checked".
        chainSkips = RuleCoverage.noEventSkipsFor(rules, atomCategoryByRuleId, all)
        if (rules.isEmpty() || all.isEmpty()) return Correlation.NONE
        val bindings = engine.computeAtomBindings(all, budget::totalExpired)
        val result = correlationEngine.evaluate(rules, all, bindings, atomRulesById, budget)
        incompleteSkips = result.incomplete
        val signals = result.signals.map { it.copy(row = it.row.copy(scanResultId = scan.id)) }
        return if (signals.isEmpty()) {
            Correlation.NONE
        } else {
            Correlation(signals, correlationEngine.findingsFor(signals, rules, atomRulesById))
        }
    }

    override fun summarize(scan: ScanResult, totals: FindingTotals): ScanResult {
        this.totals = totals
        return scan.copy(
            knownMalwareCount = totals.knownMalware,
            scannerErrors = scan.scannerErrors + synchronized(errors) { errors.toList() } + chainSkips +
                incompleteSkips,
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
 * installs, device-admin grants), a correlation lookback ([lookbackAtoms]) that excludes every
 * import source (#342 B2), and the event watermarks this scan advances (spec §5.2). Usage events
 * are store-only facts: a re-read event is the same fact, observed once (C3).
 */
@Suppress("LongParameterList") // the live scan's inputs, built once by ScanOrchestrator
internal class LiveScanHooks(
    scan: ScanResult,
    engine: SigmaRuleEngine,
    correlationEngine: SigmaCorrelationEngine,
    private val hashByPkg: Map<String, String>,
    private val detectedChanges: List<ForensicTimelineEvent>,
    private val lookbackWindowMs: Long,
    private val usage: UsageWindow,
    private val dns: DnsWindow,
    private val clock: () -> Long = System::currentTimeMillis,
    newBudget: () -> CorrelationBudget = { CorrelationBudget(::monotonicMs) },
) : WriterHooks(scan, engine, correlationEngine, newBudget) {
    /** The DNS id this scan collected through; set once every row of [DnsWindow.range] was appended. */
    var dnsCollectedThrough: Long? = null

    /** A DNS read failed mid-stream: the DNS watermark stays put. */
    var dnsReadFailed = false

    override fun watermarks(saveFallback: Boolean): Map<String, Long> = buildMap {
        Watermarks.nextTime(usage.previous, usage.collection, usage.until, clock(), saveFallback)
            ?.let { put(USAGE_STATS, it) }
        Watermarks.nextDnsId(dns.previous, dnsCollectedThrough, dns.failed || dnsReadFailed, saveFallback)
            ?.let { put(LiveRecordBuilders.DNS_MONITOR, it) }
    }

    override fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent =
        withApkHash(finding.toForensicTimelineEvent(scan), hashByPkg)

    override fun extraRows(scan: ScanResult): List<ForensicTimelineEvent> = detectedChanges

    /**
     * The correlation lookback (spec §5.2), read inside `finish` after this scan's rows were
     * inserted: visible live rows and facts a `COMPLETE` live scan observed, stamped in
     * `[scanStart - window, scanStart]`. Each guarantee is structural:
     *  - this scan's own rows and facts are not in it (its scan is still `IN_PROGRESS`, so neither
     *    [com.androdr.data.db.VisibleRow] nor a `COMPLETE` observation admits them) — they come
     *    once, from `atomsForScan`, and `correlate` also keeps each ref once;
     *  - a usage event this scan re-read is the fact an earlier scan observed; it gets no second
     *    observation (live events are observed once), so it comes once, from the lookback;
     *  - nothing stamped after the scan start, and nothing an import recorded (#342 B2: imported
     *    events carry their own historical times; a signal they helped produce would be stamped
     *    with this live scan's id, unreachable by the import's sweep).
     */
    override suspend fun lookbackAtoms(atoms: AtomReader, categories: Set<String>): List<TimelineAtom> =
        if (lookbackWindowMs <= 0L) emptyList()
        else atoms.atomsBetween(scan.timestamp - lookbackWindowMs, scan.timestamp, categories)

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
 * time. Its DNS / connect / security records are facts in the store only (C3); re-importing a log
 * observes them again under the new import and replaces nothing (spec §5.2).
 */
internal class IntrusionLogHooks(
    scan: ScanResult,
    engine: SigmaRuleEngine,
    correlationEngine: SigmaCorrelationEngine,
) : WriterHooks(scan, engine, correlationEngine) {
    override fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent =
        finding.toForensicTimelineEvent(scan, isBugreport = true).copy(
            source = "intrusion_log_analysis",
            telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT,
            // The DNS/network/security field maps carry "timestamp" and the evaluator copies scalar
            // record fields into matchContext as strings, so a finding inherits its own event's
            // time. A finding without one falls back to 0L, which the Timeline renders as "Unknown".
            startTimestamp = FindingRank.eventTimeMs(finding)
        )
}

/**
 * A bug-report import: finding rows enriched with APK hashes. The modules' records are facts in the
 * store only (C3: the hand-built module rows are retired, so ruling R17's row-to-fact pairing is
 * moot — every event binds once, as its fact).
 */
internal class BugReportHooks(
    scan: ScanResult,
    engine: SigmaRuleEngine,
    correlationEngine: SigmaCorrelationEngine,
    private val hashByPkg: Map<String, String>,
    newBudget: () -> CorrelationBudget = { CorrelationBudget(::monotonicMs) },
) : WriterHooks(scan, engine, correlationEngine, newBudget) {
    override fun findingRow(finding: Finding, scan: ScanResult): ForensicTimelineEvent =
        withApkHash(finding.toForensicTimelineEvent(scan, isBugreport = true), hashByPkg)
}

/** Appends each intrusion-log chunk's records to the writer [session]; the typed events are not kept. */
internal class IntrusionLogSessionChunks(
    private val session: ChunkedScanWriter.Session,
    private val fallbackCapturedAt: Long,
) : IntrusionLogChunks {
    override suspend fun dns(events: List<ImportedDnsEvent>, records: List<StoreRecord>) =
        put(IntrusionLogRecordBuilders.DNS_MONITOR, records)

    override suspend fun connect(events: List<NetworkTelemetry>, records: List<StoreRecord>) =
        put(IntrusionLogRecordBuilders.NETWORK_MONITOR, records)

    override suspend fun security(events: List<SecurityLogEvent>, records: List<StoreRecord>) =
        put(IntrusionLogRecordBuilders.SECURITY_LOG, records)

    private suspend fun put(service: String, records: List<StoreRecord>) {
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
