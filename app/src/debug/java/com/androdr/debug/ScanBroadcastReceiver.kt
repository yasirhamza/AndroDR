package com.androdr.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.androdr.data.db.DnsEventDao
import com.androdr.data.repo.CveRepository
import com.androdr.ioc.IndicatorUpdater
import com.androdr.ioc.KnownAppUpdater
import com.androdr.reporting.ReportFormatter
import com.androdr.scanner.ScanOrchestrator
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import com.androdr.util.appVersion
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

@AndroidEntryPoint
class ScanBroadcastReceiver : BroadcastReceiver() {

    @Inject lateinit var scanOrchestrator: ScanOrchestrator
    @Inject lateinit var dnsEventDao: DnsEventDao
    @Inject lateinit var cveRepository: CveRepository
    @Inject lateinit var indicatorUpdater: IndicatorUpdater
    @Inject lateinit var knownAppUpdater: KnownAppUpdater
    @Inject lateinit var sigmaRuleFeed: SigmaRuleFeed
    @Inject lateinit var sigmaRuleEngine: SigmaRuleEngine

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action != ACTION_SCAN && action != ACTION_UPDATE) return
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                if (action == ACTION_UPDATE) {
                    doUpdate()
                    Log.i(TAG, "Update complete")
                } else {
                    val scan = scanOrchestrator.runFullScan()
                    val dns = dnsEventDao.getRecentSnapshot()
                    val inventory = scanOrchestrator.lastAppTelemetry
                    val report = ReportFormatter.formatScanReport(
                        scan, dns, emptyList(), inventory,
                        versionName = context.appVersion().name
                    )
                    val outDir = context.getExternalFilesDir(null) ?: return@launch
                    File(outDir, "androdr_last_report.txt").writeText(report)
                    Log.i(TAG, "Scan complete, report written to ${outDir.absolutePath}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "$action failed", e)
            } finally {
                pending.finish()
            }
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun doUpdate() = coroutineScope {
        val a = async { indicatorUpdater.update() }
        val b = async { knownAppUpdater.update() }
        a.await(); b.await()
        try { sigmaRuleEngine.setRemoteRules(sigmaRuleFeed.fetch()) } catch (_: Exception) {}
        cveRepository.refresh()
        Log.i(TAG, "CVE DB: ${cveRepository.getActivelyExploitedCount()} actively exploited CVEs loaded")
    }

    companion object {
        private const val TAG = "ScanBroadcastReceiver"
        private const val ACTION_SCAN = "com.androdr.ACTION_SCAN"
        private const val ACTION_UPDATE = "com.androdr.ACTION_UPDATE"
    }
}
