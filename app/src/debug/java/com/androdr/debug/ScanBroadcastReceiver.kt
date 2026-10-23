package com.androdr.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.androdr.data.repo.CveRepository
import com.androdr.ioc.IndicatorUpdater
import com.androdr.ioc.KnownAppUpdater
import com.androdr.reporting.ReportExporter
import com.androdr.scanner.ScanOrchestrator
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
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
    @Inject lateinit var cveRepository: CveRepository
    @Inject lateinit var indicatorUpdater: IndicatorUpdater
    @Inject lateinit var knownAppUpdater: KnownAppUpdater
    @Inject lateinit var sigmaRuleFeed: SigmaRuleFeed
    @Inject lateinit var sigmaRuleEngine: SigmaRuleEngine
    @Inject lateinit var reportExporter: ReportExporter

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
                    // The one report path: the harness reads the same report a user exports,
                    // with this scan's own stored telemetry. No logcat: a log line naming a path,
                    // domain or finding title would satisfy (or trip) a harness pattern.
                    val outDir = context.getExternalFilesDir(null) ?: return@launch
                    reportExporter.writeTo(File(outDir, "androdr_last_report.txt"), scan, includeLog = false)
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
        try {
            val remote = sigmaRuleFeed.fetch()
            if (remote.isNotEmpty()) sigmaRuleEngine.setRemoteRules(remote, sigmaRuleFeed.lastRejected)
        } catch (_: Exception) {}
        cveRepository.refresh()
        Log.i(TAG, "CVE DB: ${cveRepository.getActivelyExploitedCount()} actively exploited CVEs loaded")
    }

    companion object {
        private const val TAG = "ScanBroadcastReceiver"
        private const val ACTION_SCAN = "com.androdr.ACTION_SCAN"
        private const val ACTION_UPDATE = "com.androdr.ACTION_UPDATE"
    }
}
