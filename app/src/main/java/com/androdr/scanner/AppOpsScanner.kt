package com.androdr.scanner

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import com.androdr.data.model.AppOpsTelemetry
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Collects AppOps telemetry by checking dangerous permission usage per installed package.
 *
 * Uses [AppOpsManager.unsafeCheckOpNoThrow] (public API) instead of the @SystemApi
 * [getPackagesForOps] which is unavailable to regular apps.
 */
@Singleton
class AppOpsScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {

    /** Dangerous ops to check per package. Values are AppOpsManager.OPSTR_* constants. */
    private val dangerousOps = listOf(
        AppOpsManager.OPSTR_CAMERA,
        AppOpsManager.OPSTR_RECORD_AUDIO,
        AppOpsManager.OPSTR_READ_CONTACTS,
        AppOpsManager.OPSTR_READ_CALL_LOG,
        AppOpsManager.OPSTR_FINE_LOCATION,
        AppOpsManager.OPSTR_READ_SMS,
        AppOpsManager.OPSTR_READ_EXTERNAL_STORAGE,
        // Not a public OPSTR_* constant but valid on API 26+; the per-op try/catch handles
        // any platform that doesn't recognise it.
        "android:request_install_packages"
    )

    // The inner op loop uses `continue` for null/unknown-op cases and for permission mode
    // filtering — both are necessary guard clauses, not control-flow complexity.
    @Suppress("TooGenericExceptionCaught", "LoopWithTooManyJumpStatements")
    suspend fun collectTelemetry(): List<AppOpsTelemetry> = withContext(Dispatchers.IO) {
        val opsManager = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
            ?: return@withContext emptyList()
        val pm = context.packageManager

        val results = mutableListOf<AppOpsTelemetry>()

        try {
            @Suppress("QueryPermissionsNeeded")
            val installedPackages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

            for (pkgInfo in installedPackages) {
                val packageName = pkgInfo.packageName ?: continue
                val appInfo = pkgInfo.applicationInfo ?: continue
                val isSystem = OemPackageHelper.isSystemOrOem(packageName, appInfo)
                val uid = appInfo.uid

                for (opStr in dangerousOps) {
                    val mode = try {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            opsManager.unsafeCheckOpNoThrow(opStr, uid, packageName)
                        } else {
                            @Suppress("DEPRECATION")
                            opsManager.checkOpNoThrow(opStr, uid, packageName)
                        }
                    } catch (_: Exception) {
                        continue
                    }

                    // Only record ops that are allowed (MODE_ALLOWED = 0) or foreground-only (MODE_FOREGROUND = 4)
                    if (mode == AppOpsManager.MODE_ALLOWED ||
                        (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                            mode == AppOpsManager.MODE_FOREGROUND)
                    ) {
                        results.add(AppOpsTelemetry(
                            packageName = packageName,
                            operation = opStr,
                            lastAccessTime = 0L, // not available via public API
                            lastRejectTime = 0L,
                            accessCount = 0,
                            isSystemApp = isSystem
                        ))
                    }
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
