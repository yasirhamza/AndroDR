package com.androdr.scanner

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.KnownAppCategory
import com.androdr.ioc.KnownAppResolver
import com.androdr.ioc.OemPrefixResolver
import java.security.MessageDigest
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val knownAppResolver: KnownAppResolver,
    private val oemPrefixResolver: OemPrefixResolver
) {

    private companion object {
        private const val TAG = "AppScanner"
    }

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

    /**
     * Collects per-app telemetry metadata for every installed package without performing
     * any detection or risk-scoring logic. The returned [AppTelemetry] list feeds into the
     * SIGMA rule engine which applies its own detection rules independently.
     */
    @Suppress("LongMethod", "CyclomaticComplexMethod")
    suspend fun collectTelemetry(): List<AppTelemetry> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val signingFlag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            PackageManager.GET_SIGNING_CERTIFICATES
        else
            @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES

        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        val installedPackages = try {
            pm.getInstalledPackages(
                PackageManager.GET_PERMISSIONS or signingFlag
                    or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
                    or PackageManager.GET_ACTIVITIES or PackageManager.GET_PROVIDERS
            )
        } catch (e: Exception) {
            Log.w(TAG, "collectTelemetry: getInstalledPackages extended flags failed: ${e.message}")
            try {
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            } catch (e2: Exception) {
                Log.w(TAG, "collectTelemetry: getInstalledPackages failed: ${e2.message}")
                emptyList()
            }
        }

        val telemetryList = mutableListOf<AppTelemetry>()

        @Suppress("LoopWithTooManyJumpStatements")
        for (pkg in installedPackages) {
            val packageName = pkg.packageName ?: continue
            if (packageName == "com.androdr" || packageName == "com.androdr.debug") continue
            val appInfo = pkg.applicationInfo ?: continue
            @Suppress("TooGenericExceptionCaught", "SwallowedException")
            val appName = try {
                pm.getApplicationLabel(appInfo).toString()
            } catch (e: Exception) {
                Log.w(TAG, "collectTelemetry: getApplicationLabel failed for $packageName: ${e.message}")
                packageName
            }

            val isSystemApp = appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0

            // Cert hash — skip for system apps (AOSP test key causes false positives)
            @Suppress("TooGenericExceptionCaught", "SwallowedException")
            val certHash = if (!isSystemApp) {
                try {
                    extractCertHash(pkg)
                } catch (e: Exception) {
                    Log.w(TAG, "collectTelemetry: cert hash extraction failed for $packageName: ${e.message}")
                    null
                }
            } else {
                null
            }

            // APK file hash for VirusTotal lookup
            @Suppress("TooGenericExceptionCaught", "SwallowedException")
            val apkHash = if (!isSystemApp) {
                try {
                    computeApkHash(appInfo)
                } catch (e: Exception) {
                    Log.w(TAG, "collectTelemetry: APK hash failed for $packageName: ${e.message}")
                    null
                }
            } else {
                null
            }

            // Installer source
            val installerPackage = if (!isSystemApp) getInstallerPackageName(pm, packageName) else null
            val fromTrustedStore = installerPackage != null &&
                oemPrefixResolver.isTrustedInstaller(installerPackage)

            // Known-app resolver
            val knownApp = knownAppResolver.lookup(packageName)
            // Primary: known-good DB (Plexus/UAD feeds, 14k+ apps)
            // Fallback: OEM prefix matching (for apps not in DB yet)
            val isKnownOemApp = knownApp?.category in setOf(
                KnownAppCategory.OEM, KnownAppCategory.AOSP, KnownAppCategory.GOOGLE
            ) || oemPrefixResolver.isOemPrefix(packageName)
                || (isSystemApp && oemPrefixResolver.isPartnershipPrefix(packageName))

            val isSideloaded = !isSystemApp && !fromTrustedStore && !isKnownOemApp

            // Surveillance permissions
            val grantedPermissions = pkg.requestedPermissions?.toList() ?: emptyList()
            val matchedSurveillancePerms = grantedPermissions.filter { it in surveillancePermissions }

            // Accessibility service
            val hasAccessibilityService = pkg.services?.any { svc ->
                svc.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
            } == true

            // Device admin
            val hasDeviceAdmin = pkg.receivers?.any { recv ->
                recv.permission == "android.permission.BIND_DEVICE_ADMIN"
            } == true

            // Raw component lists — enables manifest-based detections as pure rule updates.
            // getInstalledPackages may truncate component arrays due to Binder size limits,
            // so fall back to per-package getPackageInfo when services/receivers are null.
            val pkgDetail = if (pkg.services == null || pkg.receivers == null) {
                @Suppress("TooGenericExceptionCaught", "SwallowedException")
                try {
                    pm.getPackageInfo(
                        packageName,
                        PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
                    )
                } catch (e: Exception) {
                    null
                }
            } else {
                null
            }
            val servicePermissions = (pkg.services ?: pkgDetail?.services)
                ?.mapNotNull { it.permission }
                ?.distinct()
                ?: emptyList()
            val receiverPermissions = (pkg.receivers ?: pkgDetail?.receivers)
                ?.mapNotNull { it.permission }
                ?.distinct()
                ?: emptyList()
            // Launcher activity check (API call — not derivable from manifest alone)
            val hasLauncherActivity = pm.getLaunchIntentForPackage(packageName) != null

            telemetryList.add(
                AppTelemetry(
                    packageName = packageName,
                    appName = appName,
                    certHash = certHash,
                    apkHash = apkHash,
                    isSystemApp = isSystemApp,
                    fromTrustedStore = fromTrustedStore,
                    installer = installerPackage,
                    isSideloaded = isSideloaded,
                    isKnownOemApp = isKnownOemApp,
                    permissions = matchedSurveillancePerms.map { it.substringAfterLast('.') },
                    surveillancePermissionCount = matchedSurveillancePerms.size,
                    hasAccessibilityService = hasAccessibilityService,
                    hasDeviceAdmin = hasDeviceAdmin,
                    knownAppCategory = knownApp?.category?.name,
                    servicePermissions = servicePermissions,
                    receiverPermissions = receiverPermissions,
                    hasLauncherActivity = hasLauncherActivity
                )
            )
        }

        telemetryList
    }

    private fun computeApkHash(appInfo: ApplicationInfo): String? {
        val sourceDir = appInfo.sourceDir ?: return null
        val file = java.io.File(sourceDir)
        if (!file.exists()) return null
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        file.inputStream().use { stream ->
            var read: Int
            while (stream.read(buffer).also { read = it } != -1) {
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun extractCertHash(packageInfo: android.content.pm.PackageInfo): String? {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.signingInfo?.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures
        }
        val cert = signatures?.firstOrNull() ?: return null
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(cert.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    /**
     * Returns the installer package name for [packageName], handling API-level differences
     * and wrapping any SecurityException that can occur for some packages.
     */
    private fun getInstallerPackageName(pm: PackageManager, packageName: String): String? {
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // getInstallSourceInfo can
        // throw SecurityException or NameNotFoundException on restricted packages; null = unknown.
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val info = pm.getInstallSourceInfo(packageName)
                // initiatingPackageName is the app that started the install session,
                // which may differ from installingPackageName on Samsung partnership
                // pre-installs (e.g. com.facebook.system for WhatsApp).
                val installer = info.installingPackageName
                if (installer == null && info.initiatingPackageName != null) {
                    Log.d(TAG, "installingPackageName null for $packageName, " +
                        "using initiatingPackageName=${info.initiatingPackageName}")
                }
                installer ?: info.initiatingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (e: Exception) {
            Log.w(TAG, "AppScanner: getInstallerPackageName failed for $packageName: ${e.message}")
            null
        }
    }
}
