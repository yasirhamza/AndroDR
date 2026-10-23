package com.androdr.scanner

import android.util.Log
import com.androdr.data.db.DnsEventDao
import com.androdr.data.model.AccessibilityTelemetry
import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.DeviceTelemetry
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ProcessTelemetry
import com.androdr.data.model.ReceiverTelemetry
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.UsageEvent
import com.androdr.reporting.DNS_SNAPSHOT_SCANNER
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import javax.inject.Inject
import javax.inject.Singleton

/**
 * One live scan's collected telemetry (no detection logic), plus the inputs the per-service
 * watermarks will advance from (spec §5.2 Watermarks, Task C1).
 */
class LiveTelemetry(
    val apps: List<AppTelemetry>,
    val device: List<DeviceTelemetry>,
    val processes: List<ProcessTelemetry>,
    val files: List<FileArtifactTelemetry>,
    val accessibility: List<AccessibilityTelemetry>,
    val receivers: List<ReceiverTelemetry>,
    val appOps: List<AppOpsTelemetry>,
    val usage: List<UsageEvent>,
    /** The recent live DNS rows (today's snapshot window); empty when the read failed. */
    val dns: List<DnsEvent>,
) {
    /** Watermark input for live DNS: the highest `DnsEvent.id` collected. */
    val dnsMaxId: Long? get() = dns.maxOfOrNull { it.id }

    /** Watermark input for usage stats: the latest event time collected. */
    val usageMaxTime: Long? get() = usage.maxOfOrNull { it.timestamp }
}

/**
 * Collects a live scan's telemetry: the scanners run in parallel, each isolated so one failure is
 * recorded and does not zero out the scan, then the recent live DNS rows are read.
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
) {
    /**
     * Runs the [SCANNER_COUNT] scanners concurrently; [onScannerDone] runs once per scanner,
     * success or failure (progress counts wall-clock progress, failures are surfaced in [errors]).
     */
    suspend fun collect(errors: MutableList<ScannerFailure>, onScannerDone: () -> Unit): LiveTelemetry =
        coroutineScope {
            fun <T> tracked(name: String, block: suspend () -> List<T>): Deferred<List<T>> =
                trackedAsync(name, errors, onScannerDone, block)
            val apps = tracked("appScanner") { appScanner.collectTelemetry() }
            val device = tracked("deviceAuditor") { deviceAuditor.collectTelemetry() }
            val processes = tracked("processScanner") { processScanner.collectTelemetry() }
            val files = tracked("fileArtifactScanner") { fileArtifactScanner.collectTelemetry() }
            val accessibility = tracked("accessibilityAuditScanner") { accessibilityAuditScanner.collectTelemetry() }
            val receivers = tracked("receiverAuditScanner") { receiverAuditScanner.collectTelemetry() }
            val appOps = tracked("appOpsScanner") { appOpsScanner.collectTelemetry() }
            val usage = tracked("usageStatsScanner") { usageStatsScanner.collectEvents() }
            LiveTelemetry(
                apps.await(), device.await(), processes.await(), files.await(), accessibility.await(),
                receivers.await(), appOps.await(), usage.await(), recentDns(errors),
            )
        }

    /**
     * Wraps one scanner's collection: an exception (other than cancellation) is logged and
     * recorded in [errors] and the scanner contributes nothing. Silently swallowing it (the old
     * behaviour) was a detection-evasion hazard: a sample that crashed one scanner made that
     * scanner's findings disappear, indistinguishable from a real clean.
     */
    @Suppress("TooGenericExceptionCaught")
    private fun <T> CoroutineScope.trackedAsync(
        name: String,
        errors: MutableList<ScannerFailure>,
        onScannerDone: () -> Unit,
        block: suspend () -> List<T>,
    ): Deferred<List<T>> = async {
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "$name failed", e)
            synchronized(errors) {
                errors.add(ScannerFailure(scanner = name, exception = e::class.simpleName ?: "Exception",
                    message = e.message))
            }
            emptyList()
        } finally {
            onScannerDone()
        }
    }

    /** A failed read means the DNS rules did not run: recorded (#394) so the report says so. */
    @Suppress("TooGenericExceptionCaught")
    private suspend fun recentDns(errors: MutableList<ScannerFailure>): List<DnsEvent> = try {
        dnsEventDao.getRecentSnapshot()
    } catch (c: CancellationException) {
        throw c
    } catch (e: Exception) {
        Log.w(TAG, "DNS snapshot read failed; DNS rules not evaluated", e)
        synchronized(errors) {
            errors.add(ScannerFailure(scanner = DNS_SNAPSHOT_SCANNER, exception = e.javaClass.simpleName,
                message = e.message))
        }
        emptyList()
    }

    companion object {
        private const val TAG = "LiveScanCollector"

        /**
         * Number of parallel scanners tracked by the progress indicator. Keep in sync with
         * [collect] so the progress bar fills to 100%.
         */
        const val SCANNER_COUNT = 8
    }
}
