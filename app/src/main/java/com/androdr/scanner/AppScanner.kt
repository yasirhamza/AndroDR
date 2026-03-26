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
import com.androdr.ioc.IocResolver
import com.androdr.ioc.KnownAppResolver
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val iocResolver: IocResolver,
    private val knownAppResolver: KnownAppResolver
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
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // PackageManager can throw
        // undocumented RuntimeExceptions on some OEMs; returning empty list is safe fallback.
        val installedPackages = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Exception) {
            Log.w(TAG, "AppScanner: getInstalledPackages failed: ${e.message}")
            emptyList()
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

            // ── Resolver lookup ────────────────────────────────────────────
            val knownApp = knownAppResolver.lookup(packageName)
            val isKnownOemApp = knownApp?.category in setOf(
                KnownAppCategory.OEM, KnownAppCategory.AOSP, KnownAppCategory.GOOGLE
            )

            // ── 2. Dangerous permission combination scoring ────────────────
            // Only score sideloaded (untrusted-source) user apps. System apps are handled by the
            // firmware-implant check below; trusted-store apps (Play, Samsung Store, Samsung
            // ecosystem) have curated review processes that make stalkerware distribution via them
            // highly unlikely. Scoring them produces only noise.
            val isSystemApp = appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
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
