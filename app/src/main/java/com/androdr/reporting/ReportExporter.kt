package com.androdr.reporting

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.annotation.VisibleForTesting
import androidx.core.content.FileProvider
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.store.TelemetryReader
import com.androdr.util.appVersion
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.Writer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Three-way export mode selector per plan 3 (timeline UI refactor) spec Sec. 10.
 *
 * - [TELEMETRY_ONLY] writes only the telemetry section (the scan's stored records and the
 *   application log). Intended for analyst handoff: the recipient can run their own rules against
 *   the raw telemetry without being biased by the device's current ruleset.
 * - [FINDINGS_ONLY] writes only the findings section (verdict, device checks, campaign, app risks,
 *   bug report findings). Useful for sharing "what the app found" without exposing the telemetry.
 * - [BOTH] writes the full report. Default.
 */
enum class ExportMode {
    TELEMETRY_ONLY,
    FINDINGS_ONLY,
    BOTH,
}

/**
 * The one report path (spec §7, R2): every scan report is streamed by [ReportFormatter] through a
 * buffered file writer here, from the scan's own stored telemetry. The History sheet shows
 * [summary]; the export dialog states [exportEstimate]. Stale files in `cache/reports/` are removed
 * before each export (and at startup, by `StartupSweep`).
 */
@Singleton
class ReportExporter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val telemetryReader: TelemetryReader,
    private val reportInputs: ReportInputs,
    private val reportFiles: ReportFiles,
) {
    /** Streams [scan]'s report to a cached file and returns its FileProvider URI. */
    suspend fun export(scan: ScanResult, mode: ExportMode = ExportMode.BOTH): Uri = withContext(Dispatchers.IO) {
        val file = newReportFile("androdr_report", scan.timestamp)
        writeTo(file, scan, mode)
        FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    }

    /**
     * Streams [scan]'s report into [file] (the debug harness's fixed path, or [export]'s cached
     * file); a write that fails leaves no partial file behind. [includeLog] false leaves the app
     * log out (the harness: its patterns must match the report, not a log line).
     */
    suspend fun writeTo(
        file: File,
        scan: ScanResult,
        mode: ExportMode = ExportMode.BOTH,
        includeLog: Boolean = true,
    ) =
        withContext(Dispatchers.IO) {
            val findings = FindingsView.of(scan, reportInputs)
            val logLines = if (includeLog) logSource() else emptyList()
            val version = context.appVersion().name
            writeFile(file) { out ->
                ReportFormatter.writeScanReport(out, scan, findings, logLines, telemetryReader, mode, version)
            }
        }

    /** What the History sheet shows for [scan]: counts only, read off the main thread. */
    suspend fun summary(scan: ScanResult): ReportSummary = withContext(Dispatchers.IO) {
        ReportSummary(
            source = scan.source,
            overallRisk = scan.overallRiskLevel.name,
            appIssues = scan.appRisks.count { it.triggered && it.level.lowercase() != "informational" },
            deviceIssues = scan.deviceFlags.count { it.triggered },
            warningSigns = scan.activityChains.count { it.triggered },
            checksNotRun = scan.scannerErrors.count { NotEvaluatedReason.fromSentinel(it.exception) != null },
            failedScanners = scan.realFailureCount,
            telemetryState = scan.telemetryState,
            services = telemetryReader.services(scan.id),
        )
    }

    /** What a full export of [scan] carries: its record count, their size, and their categories. */
    suspend fun exportEstimate(scan: ScanResult): ExportEstimate = withContext(Dispatchers.IO) {
        val services = telemetryReader.services(scan.id)
        if (services.isEmpty()) return@withContext ExportEstimate.NONE
        val totals = telemetryReader.scanTotals(scan.id)
        ExportEstimate(totals.records, totals.rawBytes, services.map { serviceLabel(it.service) })
    }

    /** Removes stale files from `cache/reports/` (spec §7), then names `<prefix>_<time>.txt` there. */
    private fun newReportFile(prefix: String, time: Long): File {
        val dir = reportFiles.dir.apply { mkdirs() }
        runCatching { reportFiles.deleteStale() }.onFailure { Log.w(TAG, "Stale report cleanup failed", it) }
        return File(dir, "${prefix}_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date(time))}.txt")
    }

    /**
     * Streams into a `.part` sibling through a buffered UTF-8 writer, then renames it to [file], so
     * a reader polling for [file] (the debug harness) never sees a half-written report, and a write
     * that fails leaves nothing behind.
     */
    @Suppress("TooGenericExceptionCaught") // any failure removes the partial file, then rethrows
    private suspend fun writeFile(file: File, write: suspend (Writer) -> Unit) {
        val part = File(file.parentFile, "${file.name}.part")
        try {
            part.bufferedWriter(Charsets.UTF_8).use { write(it) }
            // rename(2) replaces an existing report atomically: never delete it first.
            check(part.renameTo(file)) { "could not move the report into place" }
        } catch (t: Throwable) {
            part.delete()
            throw t
        }
    }

    /** The app's own log lines, captured at export. Replaceable so tests can tell whether it is read. */
    @VisibleForTesting
    internal var logSource: () -> List<String> = ::captureLogcat

    @Suppress("TooGenericExceptionCaught")
    private fun captureLogcat(): List<String> = try {
        val pid = android.os.Process.myPid().toString()
        // Filter to AndroDR-specific tags. The previous filter (--pid + *:D)
        // captured 300+ lines of Android framework noise (ViewRootImpl,
        // InsetsController, InputMethodManager) with zero useful content.
        val tags = listOf(
            "AndroDR:D", "ScanOrchestrator:D", "AppScanner:D",
            "DeviceAuditor:D", "SigmaRuleEngine:D", "SigmaRuleEvaluator:D",
            "SigmaRuleFeed:D", "SigmaCorrelationEngine:D",
            "BugReportAnalyzer:D", "FileArtifactScanner:D",
            "OemPrefixResolver:D", "KnownSpywareArtifactsResolver:D",
            "LocalVpnService:D", "DnsInterceptor:D", "ReportExporter:D",
            "PeriodicScanWorker:D", "IocUpdateWorker:D",
            "*:W",
        )
        val cmd = listOf("logcat", "-d", "-t", "500", "--pid=$pid") + tags
        val proc = Runtime.getRuntime().exec(cmd.toTypedArray())
        proc.inputStream.bufferedReader().readLines()
            .also { proc.destroy() }
    } catch (e: Exception) {
        Log.w(TAG, "Logcat capture failed: ${e.message}")
        emptyList()
    }

    companion object {
        private const val TAG = "ReportExporter"

        // 3: telemetry sections are the scan's own stored records, one generic section per service.
        const val EXPORT_FORMAT_VERSION = 3
    }
}
