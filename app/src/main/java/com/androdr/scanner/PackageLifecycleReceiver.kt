package com.androdr.scanner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.ForensicTimelineEvent
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Listens for app install, update, and uninstall events system-wide and
 * writes a ForensicTimelineEvent for each. This provides forensic
 * traceability even when the user is not actively scanning.
 */
@AndroidEntryPoint
class PackageLifecycleReceiver : BroadcastReceiver() {

    @Suppress("LateinitUsage") // Hilt field injection requires lateinit for BroadcastReceiver
    @Inject lateinit var forensicTimelineEventDao: ForensicTimelineEventDao

    override fun onReceive(context: Context, intent: Intent) {
        val pkg = intent.data?.schemeSpecificPart ?: return
        if (pkg == context.packageName) return // ignore self

        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val (category, verb) = when (intent.action) {
                    Intent.ACTION_PACKAGE_ADDED -> {
                        if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
                            "package_updated" to "updated"
                        } else {
                            "package_installed" to "installed"
                        }
                    }
                    Intent.ACTION_PACKAGE_REMOVED -> {
                        if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
                            return@launch // update in progress, PACKAGE_ADDED will follow
                        }
                        "package_removed" to "uninstalled"
                    }
                    else -> return@launch
                }

                val appLabel = resolveAppLabel(context, pkg)
                val displayName = if (appLabel != pkg) "$appLabel ($pkg)" else pkg

                forensicTimelineEventDao.insert(ForensicTimelineEvent(
                    startTimestamp = System.currentTimeMillis(),
                    source = "package_lifecycle",
                    category = category,
                    description = "App $verb: $displayName",
                    severity = "INFO",
                    packageName = pkg,
                    appName = appLabel,
                    telemetrySource = com.androdr.data.model.TelemetrySource.LIVE_SCAN
                ))
                Log.i(TAG, "Package $verb: $displayName")
            } catch (@Suppress("TooGenericExceptionCaught") e: Exception) {
                Log.w(TAG, "Failed to record package event: ${e.message}")
            } finally {
                pending.finish()
            }
        }
    }

    @Suppress("SwallowedException", "DEPRECATION")
    private fun resolveAppLabel(context: Context, pkg: String): String = try {
        val pm = context.packageManager
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
        } else {
            pm.getApplicationInfo(pkg, 0)
        }
        pm.getApplicationLabel(info).toString()
    } catch (e: PackageManager.NameNotFoundException) {
        pkg
    }

    companion object {
        private const val TAG = "PackageLifecycle"
    }
}
