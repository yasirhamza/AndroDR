package com.androdr.scanner

import android.util.Log
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.SessionHooks
import com.androdr.data.store.DecodedRecord
import com.androdr.ioc.IndicatorResolver
import com.androdr.reporting.ATTRIBUTION_SCANNER
import com.androdr.reporting.DNS_SNAPSHOT_SCANNER
import com.androdr.sigma.BugReportRecordBuilders
import com.androdr.sigma.IntrusionLogRecordBuilders
import com.androdr.sigma.LiveRecordBuilders
import com.androdr.sigma.StoreRecord
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

// What each writer appends to its session (spec §4.1: one list, evaluated and stored), kept out of
// ScanOrchestrator so it stays within the detekt function limit.

private const val TAG = "WriterSessions"

/**
 * Opens a session for [scan] and runs [block] on it; on any failure — cancellation included — the
 * session is aborted (an unaudited cleanup delete). The failure then propagates, unless [recover]
 * is given and the failure is not a cancellation: [recover] gets the aborted session (its
 * in-memory findings are still readable) and its answer is returned.
 */
@Suppress("TooGenericExceptionCaught")
internal suspend fun <T> ChunkedScanWriter.inSession(
    scan: ScanResult, liveEvents: Boolean, hooks: SessionHooks,
    recover: ((ChunkedScanWriter.Session, Throwable) -> T)? = null,
    block: suspend (ChunkedScanWriter.Session) -> T,
): T {
    val session = begin(scan, liveEvents, hooks)
    try {
        return block(session)
    } catch (c: CancellationException) {
        session.abortKeeping(c)
        throw c
    } catch (t: Throwable) {
        session.abortKeeping(t)
        if (recover == null) throw t
        return recover(session, t)
    }
}

/** Aborts the session; a failure of the abort itself is kept on [cause] as suppressed. */
private suspend fun ChunkedScanWriter.Session.abortKeeping(cause: Throwable) =
    withContext(NonCancellable) { runCatching { abort() }.exceptionOrNull()?.let(cause::addSuppressed) }

/**
 * Thrown inside an import session whose finishing write could not be saved (`persisted = false`,
 * a full disk): the import is not in the database, so it must fail loudly (#342 B1).
 */
internal class ImportNotSavedException : IllegalStateException("the import's finishing write was not saved")

/** [written] if it was saved; otherwise the import fails ([ImportNotSavedException]). */
internal fun requireSaved(written: WriteResult): WriteResult {
    if (!written.persisted) throw ImportNotSavedException()
    return written
}

/**
 * Where a live scan reads its DNS: the domain attribution resolver, the live DNS rows by id (the
 * collected range, in chunks) and the stored live DNS facts for the late-IOC re-check.
 */
internal class LiveDnsSources(
    val indicatorResolver: IndicatorResolver,
    val rows: suspend (afterId: Long, untilId: Long, size: Int) -> List<DnsEvent>,
    val storedFacts: suspend (since: Long, afterId: Long, size: Int) -> List<DecodedRecord>,
)

/**
 * Every live service, in today's evaluation order (usage events are store-only facts, C3). Live
 * DNS is streamed by id from the DNS watermark, then the stored live DNS facts of the trailing 24 h
 * are re-checked against late IOCs (spec §5.2).
 */
internal suspend fun appendLive(
    session: ChunkedScanWriter.Session, hooks: LiveScanHooks, t: LiveTelemetry, now: Long, dns: LiveDnsSources,
) {
    suspend fun put(service: String, records: List<StoreRecord>) =
        session.appendAll(service, TelemetrySource.LIVE_SCAN, capturedAtOf(records, now), records.asSequence())
    put(LiveRecordBuilders.APP_SCANNER, LiveRecordBuilders.apps(t.apps))
    put(LiveRecordBuilders.DEVICE_AUDITOR, LiveRecordBuilders.device(t.device))
    put(LiveRecordBuilders.PROCESS_MONITOR, LiveRecordBuilders.processes(t.processes))
    put(LiveRecordBuilders.FILE_SCANNER, LiveRecordBuilders.files(t.files))
    put(LiveRecordBuilders.ACCESSIBILITY_AUDIT, LiveRecordBuilders.accessibility(t.accessibility))
    put(LiveRecordBuilders.RECEIVER_AUDIT, LiveRecordBuilders.receivers(t.receivers))
    put(LiveRecordBuilders.APPOPS_AUDIT, LiveRecordBuilders.appOps(t.appOps))
    val attribution = DnsAttribution(dns.indicatorResolver, hooks.errors)
    appendLiveDns(session, hooks, t.dns, now, dns, attribution)
    recheckStoredDns(session, hooks.errors, t.scanStart - Watermarks.LIVE_LOOKBACK_MS, dns, attribution)
    attribution.report()
    val usage = (t.usage.collection as? UsageCollection.Ok)?.events.orEmpty()
    usage.chunked(ChunkedScanWriter.CHUNK_SIZE).forEach { chunk ->
        val records = LiveRecordBuilders.usage(chunk)
        session.append(LiveRecordBuilders.USAGE_STATS, TelemetrySource.LIVE_SCAN, capturedAtOf(records, now), records)
    }
}

/**
 * Domain attribution for every DNS evaluation of one live scan: the rows behind domain hits are
 * prefetched before each chunk is evaluated, so ioc_match findings can name their family (the
 * provider reads them from this cache, never from Room on the VPN path, #71). A failed prefetch
 * costs the attribution only: findings still fire, and the scan says so, once, in [errors].
 */
internal class DnsAttribution(
    private val indicatorResolver: IndicatorResolver,
    private val errors: MutableList<ScannerFailure>,
) {
    private var prefetchFailed = false
    private val misses = HashSet<String>()

    @Suppress("TooGenericExceptionCaught")
    suspend fun prefetch(domains: Collection<String>) {
        try {
            indicatorResolver.prefetchDomainIndicators(domains)
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            Log.w(TAG, "Domain attribution prefetch failed; findings keep no family", e)
            if (!prefetchFailed) {
                errors.add(ScannerFailure(scanner = ATTRIBUTION_SCANNER, exception = e.javaClass.simpleName,
                    message = "family unavailable: domain prefetch failed"))
            }
            prefetchFailed = true
        }
    }

    /** After each evaluated chunk: the live hits it evaluated without a prefetched row. */
    fun collectMisses() {
        misses += indicatorResolver.attributionMisses.getAndSet(emptySet())
    }

    /** Once, after every DNS evaluation. After a failed prefetch every hit is a miss; that failure says so. */
    fun report() {
        if (misses.isNotEmpty() && !prefetchFailed) {
            errors.add(ScannerFailure(scanner = ATTRIBUTION_SCANNER, exception = "MissingPrefetch",
                message = "family unavailable for ${misses.size} domain(s): DNS evaluated without prefetch"))
        }
    }
}

/**
 * Live DNS by id: the rows of the collected range, [ChunkedScanWriter.CHUNK_SIZE] at a time, each
 * chunk prefetched then appended. Only once every row was appended does [LiveScanHooks] learn the
 * id collected through; a failed read is recorded (DNS rules did not run on the rest) and keeps the
 * DNS watermark. A failed append is a writer failure and propagates.
 */
@Suppress("TooGenericExceptionCaught")
private suspend fun appendLiveDns(
    session: ChunkedScanWriter.Session, hooks: LiveScanHooks, window: DnsWindow, now: Long, dns: LiveDnsSources,
    attribution: DnsAttribution,
) {
    val range = window.range ?: return
    var after = range.afterId
    while (after < range.untilId) {
        val rows = try {
            dns.rows(after, range.untilId, ChunkedScanWriter.CHUNK_SIZE)
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            dnsReadFailed(hooks.errors, "DNS read failed mid-scan; remaining DNS rows not evaluated", e)
            hooks.dnsReadFailed = true
            return
        }
        if (rows.isEmpty()) break
        attribution.prefetch(rows.map { it.domain })
        session.appendAll(LiveRecordBuilders.DNS_MONITOR, TelemetrySource.LIVE_SCAN, now,
            LiveRecordBuilders.dns(rows).asSequence())
        attribution.collectMisses()
        after = rows.last().id
    }
    hooks.dnsCollectedThrough = range.untilId
}

/**
 * Late-IOC re-check (spec §5.2): the `dns_monitor` rules re-evaluate the stored live DNS facts
 * stamped since [since] (only facts a COMPLETE live scan observed, so never this scan's own facts,
 * already evaluated by `append`, and never an import's) in keyset pages, through
 * `Session.evaluateStored`, which keeps a hit only when that rule never fired on that fact.
 */
@Suppress("TooGenericExceptionCaught")
private suspend fun recheckStoredDns(
    session: ChunkedScanWriter.Session, errors: MutableList<ScannerFailure>, since: Long, dns: LiveDnsSources,
    attribution: DnsAttribution,
) {
    var after = 0L
    while (true) {
        val page = try {
            dns.storedFacts(since, after, ChunkedScanWriter.CHUNK_SIZE)
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            dnsReadFailed(errors, "stored DNS read failed; late-IOC re-check incomplete", e)
            return
        }
        if (page.isEmpty()) return
        attribution.prefetch(page.mapNotNull { it.fields?.get("domain") as? String })
        session.evaluateStored(LiveRecordBuilders.DNS_MONITOR,
            page.asSequence().mapNotNull { r -> r.fields?.let { r.factId to StoreRecord(it) } })
        attribution.collectMisses()
        if (page.size < ChunkedScanWriter.CHUNK_SIZE) return
        after = page.last().factId
    }
}

private fun dnsReadFailed(errors: MutableList<ScannerFailure>, what: String, e: Exception) {
    Log.w(TAG, what, e)
    errors.add(ScannerFailure(scanner = DNS_SNAPSHOT_SCANNER, exception = e.javaClass.simpleName,
        message = "$what: ${e.message}"))
}

/** Generic module telemetry first (module run order), then the typed records, as evaluated today. */
internal suspend fun appendBugReport(
    session: ChunkedScanWriter.Session, result: BugReportAnalyzer.BugReportAnalysisResult, now: Long,
) {
    suspend fun put(service: String, records: List<StoreRecord>) = session.appendAll(
        service, TelemetrySource.BUGREPORT_IMPORT, capturedAtOf(records, now), records.asSequence(),
    )
    result.moduleTelemetry.forEach { put(it.service, BugReportRecordBuilders.generic(it.records)) }
    val b = result.telemetryBundle
    put(BugReportRecordBuilders.TOMBSTONE_PARSER, BugReportRecordBuilders.tombstones(b.tombstoneEvents))
    put(BugReportRecordBuilders.WAKELOCK_PARSER, BugReportRecordBuilders.wakelocks(b.wakelockAcquisitions))
    put(BugReportRecordBuilders.BATTERY_DAILY, BugReportRecordBuilders.batteryDaily(b.batteryDailyEvents))
    put(BugReportRecordBuilders.PACKAGE_INSTALL_HISTORY,
        BugReportRecordBuilders.packageInstallHistory(b.packageInstallHistory))
    put(BugReportRecordBuilders.PLATFORM_COMPAT, BugReportRecordBuilders.platformCompat(b.platformCompatChanges))
    put(BugReportRecordBuilders.DB_INFO, BugReportRecordBuilders.databasePathObservations(b.databasePathObservations))
    put(BugReportRecordBuilders.SYSTEM_PROPERTY, BugReportRecordBuilders.systemProperties(b.systemPropertySnapshots))
}

/**
 * An intrusion-log import's card: its analysis errors, and counts net of the exact duplicates the
 * store dropped. Its findings are the import scan's `scan_finding` rows (all of them, spec §5.5).
 */
internal fun intrusionLogResult(
    analysis: IntrusionLogScan, written: WriteResult,
): IntrusionLogAnalysisResult {
    val s = analysis.stats
    val triggered = written.scan.triggeredCount
    fun dropped(service: String) = written.duplicatesByService[service] ?: 0
    val stats = s.copy(
        dnsEventCount = s.dnsEventCount - dropped(IntrusionLogRecordBuilders.DNS_MONITOR),
        connectEventCount = s.connectEventCount - dropped(IntrusionLogRecordBuilders.NETWORK_MONITOR),
        securityEventCount = s.securityEventCount - dropped(IntrusionLogRecordBuilders.SECURITY_LOG),
        duplicatesCollapsed = written.duplicatesDropped,
        triggeredFindingCount = triggered,
    )
    Log.i(TAG, "Persisted intrusion-log import ${written.scan.id}: ${written.newFacts} new facts, " +
        "${written.alreadyStored} already stored, ${written.duplicatesDropped} duplicates dropped")
    return IntrusionLogAnalysisResult(stats, analysis.scannerErrors, written)
}
