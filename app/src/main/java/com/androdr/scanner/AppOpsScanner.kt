package com.androdr.scanner

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.util.Log
import com.androdr.data.model.AppOpsTelemetry
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppOpsScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {

    private val dangerousOps = arrayOf(
        AppOpsManager.OPSTR_CAMERA,
        AppOpsManager.OPSTR_RECORD_AUDIO,
        AppOpsManager.OPSTR_READ_CONTACTS,
        AppOpsManager.OPSTR_READ_CALL_LOG,
        AppOpsManager.OPSTR_FINE_LOCATION,
        AppOpsManager.OPSTR_READ_SMS,
        AppOpsManager.OPSTR_READ_EXTERNAL_STORAGE
    )

    @Suppress("TooGenericExceptionCaught")
    suspend fun collectTelemetry(): List<AppOpsTelemetry> = withContext(Dispatchers.IO) {
        val opsManager = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
            ?: return@withContext emptyList()
        val pm = context.packageManager

        val results = mutableListOf<AppOpsTelemetry>()

        try {
            val packages = opsManager.getPackagesForOps(dangerousOps)
                ?: return@withContext emptyList()

            for (pkg in packages) {
                val packageName = pkg.packageName ?: continue
                val isSystem = try {
                    val appInfo = pm.getApplicationInfo(packageName, 0)
                    appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
                } catch (_: Exception) {
                    false
                }

                val ops = pkg.ops ?: continue
                for (op in ops) {
                    val opName = op.opStr ?: continue

                    var lastAccess = 0L
                    var lastReject = 0L
                    var accessCount = 0

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        try {
                            val entries = op.attributedOpEntries
                            for ((_, entry) in entries) {
                                val access = entry.getLastAccessTime(
                                    AppOpsManager.OP_FLAGS_ALL
                                )
                                val reject = entry.getLastRejectTime(
                                    AppOpsManager.OP_FLAGS_ALL
                                )
                                if (access > lastAccess) lastAccess = access
                                if (reject > lastReject) lastReject = reject
                                accessCount++
                            }
                        } catch (_: Exception) { }
                    }

                    results.add(AppOpsTelemetry(
                        packageName = packageName,
                        operation = opName,
                        lastAccessTime = lastAccess,
                        lastRejectTime = lastReject,
                        accessCount = accessCount,
                        isSystemApp = isSystem
                    ))
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "AppOps query failed: ${e.message}")
        }

        Log.d(TAG, "Collected ${results.size} app ops records")
        results
    }

    companion object {
        private const val TAG = "AppOpsScanner"
    }
}
