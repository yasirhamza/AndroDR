package com.androdr.reporting

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.core.content.FileProvider
import com.androdr.data.db.DnsEventDao
import com.androdr.data.model.ScanResult
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
    private val dnsEventDao: DnsEventDao
) {
    private val filenameFmt = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)

    /**
     * Generates a full security report for [scan], writes it to the app's
     * cache directory, and returns a [FileProvider] URI suitable for sharing
     * via [android.content.Intent.ACTION_SEND].
     */
    suspend fun export(scan: ScanResult): Uri = withContext(Dispatchers.IO) {
        val dnsEvents = dnsEventDao.getRecentSnapshot()
        val logLines  = captureLogcat()
        val text      = ReportFormatter.formatScanReport(scan, dnsEvents, logLines)

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

    /** Captures recent log lines from this process (does not require READ_LOGS). */
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
