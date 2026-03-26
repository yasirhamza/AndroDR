package com.androdr.scanner

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import com.androdr.data.model.AppRisk
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.RiskLevel
import com.androdr.ioc.CertHashIocResolver
import com.androdr.ioc.IocResolver
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
    private val iocResolver: IocResolver,
    private val knownAppResolver: KnownAppResolver,
    private val certHashIocResolver: CertHashIocResolver
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

    @Suppress("LongMethod", "CyclomaticComplexMethod", "LoopWithTooManyJumpStatements")
    // Security scan logic requires comprehensive checks across multiple risk categories;
    // refactoring into smaller functions would obscure the holistic risk-scoring flow. The two
    // null-guard continues are the clearest way to skip invalid package entries early.
    suspend fun scan(): List<AppRisk> = withContext(Dispatchers.IO) {
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
            Log.w(TAG, "AppScanner: getInstalledPackages with extended flags failed, retrying minimal: ${e.message}")
            try {
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            } catch (e2: Exception) {
                Log.w(TAG, "AppScanner: getInstalledPackages failed: ${e2.message}")
                emptyList()
            }
        }

        val risks = mutableListOf<AppRisk>()

        for (pkg in installedPackages) {
            val packageName = pkg.packageName ?: continue
            val appInfo = pkg.applicationInfo ?: continue
            @Suppress("TooGenericExceptionCaught", "SwallowedException") // getApplicationLabel can
            // throw NameNotFoundException or OEM RuntimeExceptions; fall back to packageName.
            val appName = try {
                pm.getApplicationLabel(appInfo).toString()
            } catch (e: Exception) {
                Log.w(TAG, "AppScanner: getApplicationLabel failed for $packageName: ${e.message}")
                packageName
            }

            val reasons = mutableListOf<String>()
            var riskLevel = RiskLevel.LOW
            var isKnownMalware = false
            var isSideloaded = false

            // ── 1. IOC database check ──────────────────────────────────────
            @Suppress("TooGenericExceptionCaught", "SwallowedException") // IOC resolver can throw
            // if the database is not yet populated; null is the safe sentinel (no IOC match).
            val iocHit = try {
                iocResolver.isKnownBadPackage(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "AppScanner: IOC lookup failed for $packageName: ${e.message}")
                null
            }
            if (iocHit != null) {
                isKnownMalware = true
                riskLevel = RiskLevel.CRITICAL
                reasons.add("Package name matches known malware or stalkerware IOC database entry")
            }

            val isSystemApp = appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0

            // ── 1b. Cert hash IOC check ─────────────────────────────────
            // Skip for system apps: many malware samples are signed with the publicly
            // available AOSP test key, which also signs legitimate system components
            // like CTS shims. A cert hash match on a system app is a false positive.
            if (!isSystemApp) {
                @Suppress("TooGenericExceptionCaught", "SwallowedException")
                val certHash = try {
                    extractCertHash(pkg)
                } catch (e: Exception) {
                    Log.w(TAG, "AppScanner: cert hash extraction failed for $packageName: ${e.message}")
                    null
                }
                if (certHash != null) {
                    @Suppress("TooGenericExceptionCaught", "SwallowedException")
                    val certHit = try {
                        certHashIocResolver.isKnownBadCert(certHash)
                    } catch (e: Exception) {
                        Log.w(TAG, "AppScanner: cert hash IOC lookup failed for $packageName: ${e.message}")
                        null
                    }
                    if (certHit != null) {
                        isKnownMalware = true
                        val newLevel = RiskLevel.CRITICAL
                        if (newLevel.score > riskLevel.score) riskLevel = newLevel
                        reasons.add("Known malicious signing certificate (${certHit.familyName})")
                    }
                }
            }

            // ── Resolver lookup ────────────────────────────────────────────
            val knownApp = knownAppResolver.lookup(packageName)
            // The resolver covers packages explicitly known to community feeds. As a fallback for
            // system apps not in any feed (Samsung TTS voices, Wi-Fi resource APKs, GPU drivers,
            // etc.), use the OEM prefix list so they are not misclassified as firmware implants.
            // Samsung delivers many user apps (TV Plus, Kids, Game Launcher) via OEM
            // provisioning without FLAG_SYSTEM and with a null installer. Treat Samsung-prefixed
            // packages as OEM apps regardless of the system flag to avoid false sideload alerts.
            val isSamsungOemPackage = samsungOemPrefixes.any { packageName.startsWith(it) }
            val isKnownOemApp = knownApp?.category in setOf(
                KnownAppCategory.OEM, KnownAppCategory.AOSP, KnownAppCategory.GOOGLE
            ) || (isSystemApp && knownOemPrefixes.any { packageName.startsWith(it) })
                || isSamsungOemPackage

            // ── 2. Dangerous permission combination scoring ────────────────
            // Only score sideloaded (untrusted-source) user apps. System apps are handled by the
            // firmware-implant check below; trusted-store apps (Play, Samsung Store, Samsung
            // ecosystem) have curated review processes that make stalkerware distribution via them
            // highly unlikely. Scoring them produces only noise.
            // Compute installer source once — used by both permission scoring and sideload check.
            // Any com.samsung.* or com.sec.* package acting as an installer is a Samsung ecosystem
            // component (Watch Manager, Cloud, Update Center, etc.) and is treated as trusted.
            val installerPackage = if (!isSystemApp) getInstallerPackageName(pm, packageName) else null
            val fromTrustedStore = installerPackage != null &&
                (installerPackage in trustedInstallers ||
                    installerPackage.startsWith("com.samsung.") ||
                    installerPackage.startsWith("com.sec."))

            val grantedPermissions = pkg.requestedPermissions?.toList() ?: emptyList()
            val matchedSurveillancePerms = grantedPermissions
                .filter { it in surveillancePermissions }
            // Permission scoring only applies to non-system apps from untrusted sources.
            if (matchedSurveillancePerms.size >= 2 && !isSystemApp && !fromTrustedStore) {
                @Suppress("MaxLineLength") // Inline ternary is clearest for this threshold check
                val newLevel = if (matchedSurveillancePerms.size >= 4) RiskLevel.CRITICAL else RiskLevel.HIGH
                if (newLevel.score > riskLevel.score) riskLevel = newLevel
                @Suppress("MaxLineLength") // Permission list string is a diagnostic message; breaking
                // it would reduce readability of the reason shown to the security analyst.
                reasons.add(
                    "Holds ${matchedSurveillancePerms.size} sensitive surveillance-capable " +
                        "permissions simultaneously: ${matchedSurveillancePerms.joinToString { it.substringAfterLast('.') }}"
                )
            }

            // ── 2b. Impersonation detection ───────────────────────────────
            // A USER_APP entry sideloaded from an untrusted source is likely
            // a spoofed APK masquerading as the legitimate app.
            if (!isSystemApp && !fromTrustedStore &&
                knownApp?.category == KnownAppCategory.USER_APP) {
                val newLevel = RiskLevel.HIGH
                if (newLevel.score > riskLevel.score) riskLevel = newLevel
                reasons.add(
                    "Package name matches well-known app '${knownApp.displayName}' but was not " +
                        "installed from a trusted store — possible impersonation"
                )
            }

            // ── 3. Sideload detection ──────────────────────────────────────
            // Also skip known-OEM apps: Samsung user apps (e.g. Samsung Kids, Samsung TV
            // Plus) may not be FLAG_SYSTEM but arrive with a null installer via OEM provisioning.
            if (!isSystemApp && !fromTrustedStore && !isKnownOemApp) {
                isSideloaded = true
                val newLevel = RiskLevel.MEDIUM
                if (newLevel.score > riskLevel.score) riskLevel = newLevel
                val source = installerPackage ?: "unknown"
                reasons.add("App was not installed via a trusted app store (installer: $source)")
            }

            // ── 3b. Accessibility service / Device Admin abuse ─────────
            // Stalkerware abuses AccessibilityService for screen reading and keylogging,
            // and DeviceAdminReceiver to prevent uninstallation. Skip system apps (TalkBack,
            // MDM agents are legitimate). Escalate to CRITICAL if also sideloaded.
            if (!isSystemApp) {
                val hasAccessibilityService = pkg.services?.any { svc ->
                    svc.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
                } == true
                if (hasAccessibilityService) {
                    val newLevel = if (isSideloaded) RiskLevel.CRITICAL else RiskLevel.HIGH
                    if (newLevel.score > riskLevel.score) riskLevel = newLevel
                    reasons.add("Registered as an accessibility service")
                }

                val hasDeviceAdmin = pkg.receivers?.any { recv ->
                    recv.permission == "android.permission.BIND_DEVICE_ADMIN"
                } == true
                if (hasDeviceAdmin) {
                    val newLevel = if (isSideloaded) RiskLevel.CRITICAL else RiskLevel.HIGH
                    if (newLevel.score > riskLevel.score) riskLevel = newLevel
                    reasons.add("Registered as a device administrator")
                }
            }

            // ── 4. Pre-installed anomaly check ────────────────────────────
            if (isSystemApp) {
                if (!isKnownOemApp) {
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
