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
import java.security.MessageDigest
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val knownAppResolver: KnownAppResolver
) {

    private companion object {
        private const val TAG = "AppScanner"

        /**
         * Package prefixes for system apps that are always legitimate OEM/AOSP components.
         * Used as a fallback when [KnownAppResolver] has no entry for a system app — the resolver
         * covers well-known packages explicitly, but Samsung/Qualcomm ship hundreds of subsystem
         * packages (TTS voices, Wi-Fi resources, game drivers, etc.) that no community feed tracks.
         * Without this fallback, all unrecognised system apps would fire the firmware-implant alert.
         */
        private val knownOemPrefixes = listOf(
            // AOSP / Google
            "com.android.", "com.google.", "android",
            // Chipset vendors
            "com.qualcomm.", "com.qti.", "vendor.qti.",
            // Samsung / Knox / SEC
            "com.samsung.", "com.sec.", "com.osp.", "com.knox.",
            "com.skms.", "com.mygalaxy.", "com.monotype.", "com.hiya.",
            "com.sem.", "com.swiftkey.",
            "com.wsomacp", "com.wssyncmldm",
            // Samsung partnership pre-installs
            "com.microsoft.", "com.touchtype.",
            "com.facebook.",
            // Other common pre-installs
            "com.amazon.",
            // Other Android OEMs
            "com.motorola.", "com.oneplus.", "com.miui.", "com.lge.",
            "com.htc.", "com.sony.", "com.huawei.", "com.asus.",
            "com.oppo.", "com.realme.", "com.vivo.",
            // Custom ROMs
            "org.lineageos.", "com.cyanogenmod."
        )

        /**
         * Samsung-specific package prefixes for apps delivered via OEM provisioning
         * without FLAG_SYSTEM. These are legitimate Samsung apps (TV Plus, Kids,
         * Game Launcher, etc.) that arrive with a null installer.
         */
        private val samsungOemPrefixes = listOf(
            "com.samsung.", "com.sec.", "com.knox.", "com.osp.",
            "com.sem.", "com.skms.", "com.mygalaxy."
        )
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

    /** Trusted app store installer package names (Play Store + Samsung Galaxy Store). */
    private val trustedInstallers = setOf(
        "com.android.vending",            // Google Play Store
        "com.sec.android.app.samsungapps" // Samsung Galaxy Store
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

            // Installer source
            val installerPackage = if (!isSystemApp) getInstallerPackageName(pm, packageName) else null
            val fromTrustedStore = installerPackage != null &&
                (installerPackage in trustedInstallers ||
                    installerPackage.startsWith("com.samsung.") ||
                    installerPackage.startsWith("com.sec."))

            // Known-app resolver
            val knownApp = knownAppResolver.lookup(packageName)
            val isSamsungOemPackage = samsungOemPrefixes.any { packageName.startsWith(it) }
            val isKnownOemApp = knownApp?.category in setOf(
                KnownAppCategory.OEM, KnownAppCategory.AOSP, KnownAppCategory.GOOGLE
            ) || (isSystemApp && knownOemPrefixes.any { packageName.startsWith(it) })
                || isSamsungOemPackage

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

            telemetryList.add(
                AppTelemetry(
                    packageName = packageName,
                    appName = appName,
                    certHash = certHash,
                    isSystemApp = isSystemApp,
                    fromTrustedStore = fromTrustedStore,
                    installer = installerPackage,
                    isSideloaded = isSideloaded,
                    isKnownOemApp = isKnownOemApp,
                    permissions = matchedSurveillancePerms.map { it.substringAfterLast('.') },
                    surveillancePermissionCount = matchedSurveillancePerms.size,
                    hasAccessibilityService = hasAccessibilityService,
                    hasDeviceAdmin = hasDeviceAdmin,
                    knownAppCategory = knownApp?.category?.name
                )
            )
        }

        telemetryList
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
                pm.getInstallSourceInfo(packageName).installingPackageName
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
