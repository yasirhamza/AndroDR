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

@Singleton
class ReportExporter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val dnsEventDao: DnsEventDao,
    private val scanOrchestrator: ScanOrchestrator,
    private val appScanner: AppScanner
) {
    private val filenameFmt = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)

    suspend fun export(scan: ScanResult): Uri = withContext(Dispatchers.IO) {
        val dnsEvents = dnsEventDao.getRecentSnapshot()
        val logLines  = captureLogcat()
        val inventory = scanOrchestrator.lastAppTelemetry.ifEmpty {
            runCatching { appScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
        val text      = ReportFormatter.formatScanReport(scan, dnsEvents, logLines, inventory)

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
    }
}
