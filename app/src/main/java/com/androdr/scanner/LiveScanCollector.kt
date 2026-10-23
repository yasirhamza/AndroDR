package com.androdr.scanner

import android.util.Log
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.EventWatermarkDao
import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.DeviceTelemetry
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ProcessTelemetry
import com.androdr.data.model.ReceiverTelemetry
import com.androdr.data.model.ScannerFailure
import com.androdr.reporting.DNS_SNAPSHOT_SCANNER
import com.androdr.sigma.LiveRecordBuilders
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import javax.inject.Inject
import javax.inject.Singleton

/**
 * One live scan's collected telemetry (no detection logic). Live events are collected from their
 * per-service watermarks (spec §5.2 Watermarks): [usage] holds the usage events read since the
 * usage watermark; [dns] is only the id range of live DNS rows to read — the session streams them
 * in chunks, so a scan after a long gap never holds every row at once.
 */
class LiveTelemetry(
    val apps: List<AppTelemetry>,
    val device: List<DeviceTelemetry>,
    val processes: List<ProcessTelemetry>,
    val files: List<FileArtifactTelemetry>,
    val accessibility: List<AccessibilityTelemetry>,
    val receivers: List<ReceiverTelemetry>,
    val appOps: List<AppOpsTelemetry>,
    val usage: UsageWindow,
    val dns: DnsWindow,
    /** When collection started: no watermark moves past it; the late-IOC re-check window ends here. */
    val scanStart: Long,
)

/**
 * Collects a live scan's telemetry: the scanners run in parallel, each isolated so one failure is
 * recorded and does not zero out the scan, then the live DNS id range is read.
 */
@Singleton
@Suppress("LongParameterList") // All parameters are Hilt-injected scanners
class LiveScanCollector @Inject constructor(
    private val appScanner: AppScanner,
    private val deviceAuditor: DeviceAuditor,
    private val processScanner: ProcessScanner,
    private val fileArtifactScanner: FileArtifactScanner,
    private val accessibilityAuditScanner: AccessibilityAuditScanner,
    private val receiverAuditScanner: ReceiverAuditScanner,
    private val appOpsScanner: AppOpsScanner,
    private val usageStatsScanner: UsageStatsScanner,
    private val dnsEventDao: DnsEventDao,
    private val watermarks: EventWatermarkDao,
) {
    /**
     * Runs the [SCANNER_COUNT] scanners concurrently; [onScannerDone] runs once per scanner,
     * success or failure (progress counts wall-clock progress, failures are surfaced in [errors]).
     * [scanStart] ends the usage window and bounds the watermarks.
     */
    suspend fun collect(
        errors: MutableList<ScannerFailure>, scanStart: Long, onScannerDone: () -> Unit,
    ): LiveTelemetry =
        coroutineScope {
            fun <T> tracked(name: String, block: suspend () -> List<T>): Deferred<List<T>> =
                trackedAsync(name, errors, onScannerDone, { emptyList() }, block)
            val apps = tracked("appScanner") { appScanner.collectTelemetry() }
            val device = tracked("deviceAuditor") { deviceAuditor.collectTelemetry() }
            val processes = tracked("processScanner") { processScanner.collectTelemetry() }
            val files = tracked("fileArtifactScanner") { fileArtifactScanner.collectTelemetry() }
            val accessibility = tracked("accessibilityAuditScanner") { accessibilityAuditScanner.collectTelemetry() }
            val receivers = tracked("receiverAuditScanner") { receiverAuditScanner.collectTelemetry() }
            val appOps = tracked("appOpsScanner") { appOpsScanner.collectTelemetry() }
            val usage = trackedAsync(USAGE_SCANNER, errors, onScannerDone,
                { e -> UsageWindow(null, scanStart, scanStart, UsageCollection.Failed(e)) }) {
                usageWindow(scanStart, errors)
            }
            LiveTelemetry(
                apps.await(), device.await(), processes.await(), files.await(), accessibility.await(),
                receivers.await(), appOps.await(), usage.await(), dnsWindow(scanStart, errors), scanStart,
            )
        }

    /**
     * Usage events since the usage watermark (re-read [Watermarks.USAGE_REREAD_MS] before it). A
     * failed query is recorded like a crashed scanner; no Usage Access is not a failure (the
     * Dashboard banner asks for it), but neither collection moves the watermark.
     */
    private suspend fun usageWindow(scanStart: Long, errors: MutableList<ScannerFailure>): UsageWindow {
        val previous = watermarks.get(USAGE_STATS)?.position
        val since = Watermarks.usageSince(previous, scanStart)
        val collection = usageStatsScanner.collectEvents(since, scanStart)
        if (collection is UsageCollection.Failed) {
            Log.w(TAG, "$USAGE_SCANNER failed", collection.e)
            synchronized(errors) { errors.add(failure(USAGE_SCANNER, collection.e)) }
        }
        return UsageWindow(previous, since, scanStart, collection)
    }

    /** Up to [size] live DNS rows with ids in `(afterId, untilId]`, ascending (the session's chunks). */
    suspend fun dnsRows(afterId: Long, untilId: Long, size: Int): List<DnsEvent> =
        dnsEventDao.eventsAfterId(afterId, untilId, size)

    /**
     * Wraps one scanner's collection: an exception (other than cancellation) is logged and
     * recorded in [errors] and the scanner contributes [fallback]. Silently swallowing it (the old
     * behaviour) was a detection-evasion hazard: a sample that crashed one scanner made that
     * scanner's findings disappear, indistinguishable from a real clean.
     */
    @Suppress("TooGenericExceptionCaught")
    private fun <T> CoroutineScope.trackedAsync(
        name: String,
        errors: MutableList<ScannerFailure>,
        onScannerDone: () -> Unit,
        fallback: (Exception) -> T,
        block: suspend () -> T,
    ): Deferred<T> = async {
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "$name failed", e)
            synchronized(errors) { errors.add(failure(name, e)) }
            fallback(e)
        } finally {
            onScannerDone()
        }
    }

    private fun failure(name: String, e: Throwable) =
        ScannerFailure(scanner = name, exception = e::class.simpleName ?: "Exception", message = e.message)

    /**
     * The live DNS id range after the DNS watermark. A failed read means the DNS rules did not run:
     * recorded (#394) so the report says so, and the watermark stays put.
     */
    @Suppress("TooGenericExceptionCaught")
    private suspend fun dnsWindow(scanStart: Long, errors: MutableList<ScannerFailure>): DnsWindow {
        var previous: Long? = null
        return try {
            previous = watermarks.get(DNS_MONITOR)?.position
            DnsWindow(previous, DnsRange.of(dnsEventDao, previous, scanStart), failed = false)
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            Log.w(TAG, "DNS range read failed; DNS rules not evaluated", e)
            synchronized(errors) {
                errors.add(ScannerFailure(scanner = DNS_SNAPSHOT_SCANNER, exception = e.javaClass.simpleName,
                    message = e.message))
            }
            DnsWindow(previous, null, failed = true)
        }
    }

    companion object {
        private const val TAG = "LiveScanCollector"
        private const val USAGE_SCANNER = "usageStatsScanner"
        private const val USAGE_STATS = LiveRecordBuilders.USAGE_STATS
        private const val DNS_MONITOR = LiveRecordBuilders.DNS_MONITOR

        /**
         * Number of parallel scanners tracked by the progress indicator. Keep in sync with
         * [collect] so the progress bar fills to 100%.
         */
        const val SCANNER_COUNT = 8
    }
}
