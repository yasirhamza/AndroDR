package com.androdr.scanner

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import com.androdr.data.model.AppOpsTelemetry
import com.androdr.data.model.TelemetrySource
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

    /**
     * Dangerous ops to check, paired with the Android runtime permission that gates each.
     * An op is only recorded if the package's manifest *declares* the matching permission —
     * otherwise `unsafeCheckOpNoThrow` returns the default policy mode (often `MODE_ALLOWED`)
     * for ops the app never requested, producing false-positive "camera/mic access" findings
     * on apps that never declared those permissions. See #147.
     *
     * `android:request_install_packages` lacks a public `OPSTR_*` constant but is valid on
     * API 26+; the per-op try/catch handles platforms that don't recognise it.
     */
    private val opPermissionPairs = listOf(
        AppOpsManager.OPSTR_CAMERA               to "android.permission.CAMERA",
        AppOpsManager.OPSTR_RECORD_AUDIO         to "android.permission.RECORD_AUDIO",
        AppOpsManager.OPSTR_READ_CONTACTS        to "android.permission.READ_CONTACTS",
        AppOpsManager.OPSTR_READ_CALL_LOG        to "android.permission.READ_CALL_LOG",
        AppOpsManager.OPSTR_FINE_LOCATION        to "android.permission.ACCESS_FINE_LOCATION",
        AppOpsManager.OPSTR_READ_SMS             to "android.permission.READ_SMS",
        AppOpsManager.OPSTR_READ_EXTERNAL_STORAGE to "android.permission.READ_EXTERNAL_STORAGE",
        "android:request_install_packages"       to "android.permission.REQUEST_INSTALL_PACKAGES",
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
                val isSystem = appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
                val uid = appInfo.uid
                val declaredPermissions = pkgInfo.requestedPermissions?.toSet() ?: emptySet()

                for ((opStr, permission) in opPermissionPairs) {
                    if (permission !in declaredPermissions) continue

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
                            isSystemApp = isSystem,
                            source = TelemetrySource.LIVE_SCAN,
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
