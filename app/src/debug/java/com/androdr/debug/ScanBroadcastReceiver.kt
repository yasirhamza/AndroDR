package com.androdr.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.androdr.data.db.DnsEventDao
import com.androdr.reporting.ReportFormatter
import com.androdr.scanner.ScanOrchestrator
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

@AndroidEntryPoint
class ScanBroadcastReceiver : BroadcastReceiver() {

    @Inject lateinit var scanOrchestrator: ScanOrchestrator
    @Inject lateinit var dnsEventDao: DnsEventDao

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "com.androdr.ACTION_SCAN") return
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val scan = scanOrchestrator.runFullScan()
                val dns = dnsEventDao.getRecentSnapshot()
                val report = ReportFormatter.formatScanReport(scan, dns, emptyList())
                val outDir = context.getExternalFilesDir(null) ?: return@launch
                File(outDir, "androdr_last_report.txt").writeText(report)
                Log.i(TAG, "Scan complete, report written to ${outDir.absolutePath}")
            } catch (e: Exception) {
                Log.e(TAG, "Scan failed", e)
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        private const val TAG = "ScanBroadcastReceiver"
    }
}
