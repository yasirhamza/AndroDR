package com.androdr.scanner

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.androdr.data.model.AppRisk
import com.androdr.data.model.RiskLevel
import com.androdr.ioc.IocDatabase
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val iocDatabase: IocDatabase
) {

    /**
     * Dangerous permission combinations that, when two or more appear together,
     * suggest a high-risk surveillance or data-exfiltration capability.
     */
    private val surveillancePermissions = setOf(
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.READ_CONTACTS,
        Manifest.permission.READ_CALL_LOG,
        Manifest.permission.PROCESS_OUTGOING_CALLS,
        Manifest.permission.READ_SMS,
        Manifest.permission.SEND_SMS,
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.CAMERA,
        Manifest.permission.READ_EXTERNAL_STORAGE
    )

    /** The official Play Store installer package name. */
    private val playStoreInstaller = "com.android.vending"

    suspend fun scan(): List<AppRisk> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val installedPackages = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Exception) {
            emptyList()
        }

        val risks = mutableListOf<AppRisk>()

        for (pkg in installedPackages) {
            val packageName = pkg.packageName ?: continue
            val appInfo = pkg.applicationInfo ?: continue
            val appName = try {
                pm.getApplicationLabel(appInfo).toString()
            } catch (e: Exception) {
                packageName
            }

            val reasons = mutableListOf<String>()
            var riskLevel = RiskLevel.LOW
            var isKnownMalware = false
            var isSideloaded = false

            // ── 1. IOC database check ──────────────────────────────────────
            val iocHit = try {
                iocDatabase.isKnownBadPackage(packageName)
            } catch (e: Exception) {
                false
            }
            if (iocHit) {
                isKnownMalware = true
                riskLevel = RiskLevel.CRITICAL
                reasons.add("Package name matches known malware or stalkerware IOC database entry")
            }

            // ── 2. Dangerous permission combination scoring ────────────────
            val grantedPermissions = pkg.requestedPermissions?.toList() ?: emptyList()
            val matchedSurveillancePerms = grantedPermissions
                .filter { it in surveillancePermissions }
            if (matchedSurveillancePerms.size >= 2) {
                val newLevel = if (matchedSurveillancePerms.size >= 4) RiskLevel.CRITICAL else RiskLevel.HIGH
                if (newLevel.score > riskLevel.score) riskLevel = newLevel
                reasons.add(
                    "Holds ${matchedSurveillancePerms.size} sensitive surveillance-capable " +
                        "permissions simultaneously: ${matchedSurveillancePerms.joinToString { it.substringAfterLast('.') }}"
                )
            }

            // ── 3. Sideload detection ──────────────────────────────────────
            val isSystemApp = appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
            if (!isSystemApp) {
                val installerPackage = getInstallerPackageName(pm, packageName)
                if (installerPackage != playStoreInstaller) {
                    isSideloaded = true
                    val newLevel = RiskLevel.MEDIUM
                    if (newLevel.score > riskLevel.score) riskLevel = newLevel
                    val source = installerPackage ?: "unknown"
                    reasons.add("App was not installed via Google Play Store (installer: $source)")
                }
            }

            // ── 4. Pre-installed anomaly check ────────────────────────────
            if (isSystemApp) {
                val knownSystemPrefixes = listOf(
                    "com.android.", "com.google.", "android", "com.qualcomm.",
                    "com.samsung.", "com.sec.", "com.motorola.", "com.oneplus.",
                    "com.miui.", "com.lge.", "com.htc.", "com.sony.",
                    "com.huawei.", "com.asus.", "com.oppo.", "com.realme.",
                    "com.vivo.", "org.lineageos.", "com.cyanogenmod."
                )
                val looksLikeKnownSystem = knownSystemPrefixes.any { packageName.startsWith(it) }
                if (!looksLikeKnownSystem) {
                    val newLevel = RiskLevel.HIGH
                    if (newLevel.score > riskLevel.score) riskLevel = newLevel
                    reasons.add(
                        "App has system-level privileges (FLAG_SYSTEM) but does not match any " +
                            "known OEM or AOSP package prefix — possible firmware implant"
                    )
                }
            }

            // Only include in results if there is at least one reason to flag it,
            // or if it is known malware.
            if (reasons.isNotEmpty()) {
                risks.add(
                    AppRisk(
                        packageName = packageName,
                        appName = appName,
                        riskLevel = riskLevel,
                        reasons = reasons.toList(),
                        isKnownMalware = isKnownMalware,
                        isSideloaded = isSideloaded,
                        dangerousPermissions = matchedSurveillancePerms
                    )
                )
            }
        }

        risks.sortedByDescending { it.riskLevel.score }
    }

    /**
     * Returns the installer package name for [packageName], handling API-level differences
     * and wrapping any SecurityException that can occur for some packages.
     */
    private fun getInstallerPackageName(pm: PackageManager, packageName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (e: Exception) {
            null
        }
    }
}
