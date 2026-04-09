package com.androdr.reporting

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.core.content.FileProvider
import com.androdr.data.db.DnsEventDao
import com.androdr.data.model.ScanResult
import com.androdr.scanner.AppScanner
import com.androdr.scanner.ScanOrchestrator
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Three-way export mode selector per plan 3 (timeline UI refactor) spec Sec. 10.
 *
 * - [TELEMETRY_ONLY] writes only the telemetry section (DNS activity, app
 *   hash inventory, application log). Intended for analyst handoff: the
 *   recipient can run their own rules against the raw telemetry without
 *   being biased by the device's current ruleset.
 * - [FINDINGS_ONLY] writes only the findings section (verdict, device
 *   checks, campaign, app risks, bug report findings). Useful for sharing
 *   "what the app found" without exposing the raw telemetry.
 * - [BOTH] writes the full report. Default, preserves existing behaviour.
 */
enum class ExportMode {
    TELEMETRY_ONLY,
    FINDINGS_ONLY,
    BOTH,
}

@Singleton
class ReportExporter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val dnsEventDao: DnsEventDao,
    private val scanOrchestrator: ScanOrchestrator,
    private val appScanner: AppScanner
) {
    private val filenameFmt = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)

    suspend fun export(
        scan: ScanResult,
        mode: ExportMode = ExportMode.BOTH,
    ): Uri = withContext(Dispatchers.IO) {
        val dnsEvents = dnsEventDao.getRecentSnapshot()
        val logLines  = captureLogcat()
        val inventory = scanOrchestrator.lastAppTelemetry.ifEmpty {
            runCatching { appScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
        val displayNames = inventory
            .associate { it.packageName to it.appName }
            .filterValues { it.isNotEmpty() }
        val text = ReportFormatter.formatScanReport(
            scan, dnsEvents, logLines, inventory, displayNames, mode
        )

        val reportsDir = File(context.cacheDir, "reports").apply { mkdirs() }
        val filename = "androdr_report_${filenameFmt.format(Date(scan.timestamp))}.txt"
        val reportFile = File(reportsDir, filename)
        reportFile.writeText(text, Charsets.UTF_8)

        FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            reportFile
        )
    }

    @Suppress("TooGenericExceptionCaught")
    private fun captureLogcat(): List<String> = try {
        val pid = android.os.Process.myPid().toString()
        val proc = Runtime.getRuntime().exec(
            arrayOf("logcat", "-d", "-t", "300", "--pid=$pid", "*:D")
        )
        proc.inputStream.bufferedReader().readLines()
            .also { proc.destroy() }
    } catch (e: Exception) {
        Log.w(TAG, "Logcat capture failed: ${e.message}")
        emptyList()
    }

    companion object {
        private const val TAG = "ReportExporter"

        // plan 3 refactor: explicit TELEMETRY / FINDINGS sections,
        // severity removed from telemetry rows. Bumped from 1 to 2.
        const val EXPORT_FORMAT_VERSION = 2
    }
}
