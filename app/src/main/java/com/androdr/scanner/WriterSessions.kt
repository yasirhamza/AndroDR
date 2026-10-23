package com.androdr.scanner

import android.util.Log
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.SessionHooks
import com.androdr.ioc.IndicatorResolver
import com.androdr.reporting.ATTRIBUTION_SCANNER
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
 * session is aborted (an unaudited cleanup delete) before the failure propagates.
 */
@Suppress("TooGenericExceptionCaught")
internal suspend fun <T> ChunkedScanWriter.inSession(
    scan: ScanResult, liveEvents: Boolean, hooks: SessionHooks, block: suspend (ChunkedScanWriter.Session) -> T,
): T {
    val session = begin(scan, liveEvents, hooks)
    try {
        return block(session)
    } catch (t: Throwable) {
        withContext(NonCancellable) { runCatching { session.abort() }.exceptionOrNull()?.let(t::addSuppressed) }
        throw t
    }
}

/** Every live service, in today's evaluation order; usage chunks also feed today's usage rows. */
internal suspend fun appendLive(
    session: ChunkedScanWriter.Session, hooks: LiveScanHooks, t: LiveTelemetry, now: Long,
    indicatorResolver: IndicatorResolver,
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
    appendLiveDns(session, t.dns, hooks.errors, now, indicatorResolver)
    t.usage.chunked(ChunkedScanWriter.CHUNK_SIZE).forEach { chunk ->
        hooks.interim.stage(LiveRecordBuilders.USAGE_STATS, chunk)
        val records = LiveRecordBuilders.usage(chunk)
        session.append(LiveRecordBuilders.USAGE_STATS, TelemetrySource.LIVE_SCAN, capturedAtOf(records, now), records)
    }
}

/**
 * Live DNS: the rows behind domain hits are prefetched first so ioc_match findings can name their
 * family (the provider reads them from this cache, never from Room on the VPN path, #71). A failed
 * prefetch costs the attribution only: findings still fire, and the scan says so in [errors].
 */
@Suppress("TooGenericExceptionCaught")
private suspend fun appendLiveDns(
    session: ChunkedScanWriter.Session, dns: List<DnsEvent>, errors: MutableList<ScannerFailure>, now: Long,
    indicatorResolver: IndicatorResolver,
) {
    if (dns.isEmpty()) return
    var prefetchFailed = false
    try {
        indicatorResolver.prefetchDomainIndicators(dns.map { it.domain })
    } catch (c: CancellationException) {
        throw c
    } catch (e: Exception) {
        Log.w(TAG, "Domain attribution prefetch failed; findings keep no family", e)
        prefetchFailed = true
        errors.add(ScannerFailure(scanner = ATTRIBUTION_SCANNER, exception = e.javaClass.simpleName,
            message = "family unavailable: domain prefetch failed"))
    }
    session.appendAll(LiveRecordBuilders.DNS_MONITOR, TelemetrySource.LIVE_SCAN, now,
        LiveRecordBuilders.dns(dns).asSequence())
    val misses = indicatorResolver.attributionMisses.getAndSet(emptySet())
    // After a failed prefetch every live hit is a miss; that failure already says so.
    if (misses.isNotEmpty() && !prefetchFailed) {
        errors.add(ScannerFailure(scanner = ATTRIBUTION_SCANNER, exception = "MissingPrefetch",
            message = "family unavailable for ${misses.size} domain(s): DNS evaluated without prefetch"))
    }
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
 * An intrusion-log import's card: the kept findings (capped), its analysis errors, and counts net
 * of the exact duplicates the store dropped; `triggeredFindingCount` counts past the cap.
 */
internal fun intrusionLogResult(
    analysis: IntrusionLogScan, written: WriteResult, hooks: IntrusionLogHooks,
): IntrusionLogAnalysisResult {
    val s = analysis.stats
    val triggered = hooks.totals?.triggered?.toInt() ?: written.scan.findings.count { it.triggered }
    if (triggered > ScanOrchestrator.FINDINGS_PERSIST_CAP) {
        Log.w(TAG, "Intrusion-log findings cap kept ${ScanOrchestrator.FINDINGS_PERSIST_CAP} of $triggered " +
            "triggered findings. Detection saw the full stream; only persistence is bounded.")
    }
    val stats = s.copy(
        dnsEventCount = s.dnsEventCount - hooks.interim.unobserved(IntrusionLogRecordBuilders.DNS_MONITOR),
        connectEventCount = s.connectEventCount - hooks.interim.unobserved(IntrusionLogRecordBuilders.NETWORK_MONITOR),
        securityEventCount = s.securityEventCount - hooks.interim.unobserved(IntrusionLogRecordBuilders.SECURITY_LOG),
        duplicatesCollapsed = written.duplicatesDropped,
        triggeredFindingCount = triggered,
    )
    Log.i(TAG, "Persisted intrusion-log import ${written.scan.id}: ${written.newFacts} new facts, " +
        "${written.alreadyStored} already stored, ${written.duplicatesDropped} duplicates dropped")
    return IntrusionLogAnalysisResult(written.scan.findings, stats, analysis.scannerErrors, written)
}
