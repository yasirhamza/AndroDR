package com.androdr.scanner

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.annotation.VisibleForTesting
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.KnownAppCategory
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.KnownAppResolver
import com.androdr.ioc.OemPrefixResolver
import java.security.MessageDigest
import java.util.zip.ZipFile
import android.content.pm.PackageInfo
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val knownAppResolver: KnownAppResolver,
    private val oemPrefixResolver: OemPrefixResolver
) {

    private val localDevice = DeviceIdentity.local()

    companion object {
        private const val TAG = "AppScanner"
        private const val WEBAPK_PACKAGE_PREFIX = "org.chromium.webapk."
        private const val WEBAPK_META_SCOPE = "org.chromium.webapk.shell_apk.scope"
        private const val WEBAPK_META_START_URL = "org.chromium.webapk.shell_apk.startUrl"

        /**
         * Maximum number of concurrent per-package workers in
         * [collectTelemetry]. APK-file hashing is the dominant cost and
         * is I/O-bound (reading the APK) plus CPU-bound (SHA-256), so
         * benefits from overlapping while still being storage-bandwidth
         * constrained. 16 is a pragmatic balance for modern Android
         * devices (8-12 cores, UFS 3.x/4.x storage): wide enough to
         * overlap I/O waits meaningfully, narrow enough to avoid
         * thrashing the storage queue or saturating the CPU schedulers.
         */
        private const val TELEMETRY_PARALLELISM = 16

        // NEW (#168):
        private const val MAX_COMPONENTS_PER_APP = 1024
        private const val MAX_NATIVE_LIBS_PER_APP = 256

        /**
         * Dangerous permission combinations that, when two or more appear together,
         * suggest a high-risk surveillance or data-exfiltration capability. Counted
         * by [AppTelemetry.surveillancePermissionCount].
         */
        private val SURVEILLANCE_PERMISSIONS = setOf(
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
         * High-risk permissions that are NOT surveillance signals but are abused by
         * malware — e.g. SYSTEM_ALERT_WINDOW (banking-trojan credential overlays),
         * NFC (card-emulation relay fraud), and RECEIVE_SMS (real-time interception
         * of incoming OTP/2FA texts by SMS-stealing bankers). Surfaced in the
         * `permissions` telemetry field (short-named) so combo rules can match them,
         * but deliberately excluded from [AppTelemetry.surveillancePermissionCount]
         * so they do not inflate the surveillance-cluster rules (androdr-011/017).
         *
         * RECEIVE_SMS lives here rather than in [SURVEILLANCE_PERMISSIONS] on
         * purpose: unlike READ_SMS (reading the stored inbox — genuine surveillance),
         * RECEIVE_SMS is an interception/fraud enabler that is extremely common in
         * legitimate OTP-autofill apps, so counting it toward the surveillance
         * cluster would be a large false-positive driver. It is matchable for the
         * multi-condition OTP-theft rule (androdr-089) without that side effect.
         */
        private val HIGH_RISK_PERMISSIONS = setOf(
            Manifest.permission.SYSTEM_ALERT_WINDOW,
            Manifest.permission.NFC,
            Manifest.permission.RECEIVE_SMS
        )

        /**
         * The exact set of short-named permissions the scanner places in
         * [AppTelemetry.permissions]. This is the SINGLE SOURCE OF TRUTH for which
         * permissions a SIGMA rule can match via `permissions|contains`.
         * `PermissionLiteralCrossCheckTest` asserts every bundled rule's permission
         * literal is a member — closing the dead-rule class that silently killed
         * androdr-069 (a rule referenced a permission the scanner never emitted; #225).
         */
        @VisibleForTesting
        internal val EXPOSED_PERMISSION_SHORT_NAMES: Set<String> =
            (SURVEILLANCE_PERMISSIONS + HIGH_RISK_PERMISSIONS)
                .map { it.substringAfterLast('.') }
                .toSet()
    }


    /**
     * Collects per-app telemetry metadata for every installed package without performing
     * any detection or risk-scoring logic. The returned [AppTelemetry] list feeds into the
     * SIGMA rule engine which applies its own detection rules independently.
     *
     * ## Parallelism
     *
     * The per-package work (in particular APK-file SHA-256 hashing, which
     * reads and digests the entire APK) is I/O- and CPU-intensive, and was
     * previously done in a serial `for` loop. On a real Samsung Galaxy S25
     * Ultra with ~500 installed packages this serial loop took ~14 seconds
     * of wall time and dominated the entire runtime-scan duration —
     * measured live on-device during stress testing before this change.
     *
     * The refactor here keeps the per-package work logic completely
     * unchanged (extracted into [buildTelemetryForPackage]) and dispatches
     * it across a bounded concurrent worker pool via
     * [Dispatchers.IO.limitedParallelism]. Each package becomes an
     * independent `async { ... }` task, the results are collected via
     * `awaitAll()`, and packages filtered out (self-scan exclusion,
     * missing applicationInfo) return `null` and are dropped. The
     * [TELEMETRY_PARALLELISM] bound prevents thrashing storage bandwidth
     * while still overlapping I/O waits.
     *
     * Each worker only reads from [PackageManager] (thread-safe),
     * [knownAppResolver] and [oemPrefixResolver] (read from immutable
     * in-memory caches), and the local [pkg]/[pm] it received — so no
     * explicit synchronization is needed in the worker body.
     */
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

        @Suppress("OPT_IN_USAGE")
        val workerDispatcher = Dispatchers.IO.limitedParallelism(TELEMETRY_PARALLELISM)

        val telemetryList = coroutineScope {
            installedPackages
                .map { pkg ->
                    async(workerDispatcher) { buildTelemetryForPackage(pm, pkg) }
                }
                .awaitAll()
                .filterNotNull()
        }

        Log.d(TAG, "collectTelemetry: ${telemetryList.size} apps, " +
            "${telemetryList.count { it.embeddedComponentClasses.isNotEmpty() }} with components, " +
            "${telemetryList.count { it.embeddedNativeLibs.isNotEmpty() }} with native libs")

        telemetryList
    }

    /**
     * Builds a single [AppTelemetry] entry for [pkg]. Returns `null` for
     * packages that should be skipped (self-scan exclusion, missing
     * ApplicationInfo). Extracted from [collectTelemetry] so the heavy
     * per-package body (cert-hash extraction, APK-file hashing,
     * component enumeration) can run concurrently on a bounded worker
     * pool without any shared mutable state.
     *
     * Thread-safety: this function is called from many coroutines in
     * parallel. It only reads from its parameters and from singleton
     * resolvers that hold immutable in-memory state. It does not mutate
     * anything the caller can observe beyond its return value.
     */
    @Suppress("LongMethod", "CyclomaticComplexMethod", "ReturnCount")
    private fun buildTelemetryForPackage(
        pm: PackageManager,
        pkg: PackageInfo
    ): AppTelemetry? {
        val packageName = pkg.packageName ?: return null
        if (packageName == "com.androdr" || packageName == "com.androdr.debug") return null
        val appInfo = pkg.applicationInfo ?: return null

        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        val appName = try {
            pm.getApplicationLabel(appInfo).toString()
        } catch (e: Exception) {
            Log.w(TAG, "collectTelemetry: getApplicationLabel failed for $packageName: ${e.message}")
            packageName
        }

        val isSystemApp = appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0

        // Cert hashes (SHA-256 + SHA-1) — skip for system apps (AOSP test key causes FPs)
        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        val certHashes = if (!isSystemApp) {
            try {
                extractCertHashes(pkg)
            } catch (e: Exception) {
                Log.w(TAG, "collectTelemetry: cert hash extraction failed for $packageName: ${e.message}")
                null
            }
        } else {
            null
        }
        val certHash = certHashes?.sha256
        val certHashSha1 = certHashes?.sha1

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
            oemPrefixResolver.isTrustedInstaller(installerPackage, localDevice)

        // Known-app resolver
        val knownApp = knownAppResolver.lookup(packageName)
        // Primary: known-good DB (Plexus/UAD feeds, 14k+ apps, including Samsung/Xiaomi/etc.
        //   partner preloads classified as OEM via UAD-ng's Oem/Carrier/Misc lists)
        // Fallback: OEM prefix matching (for apps not in DB yet)
        val isKnownOemApp = knownApp?.category in setOf(
            KnownAppCategory.OEM, KnownAppCategory.AOSP, KnownAppCategory.GOOGLE
        ) || oemPrefixResolver.isOemPrefix(packageName, localDevice)

        val isSideloaded = !isSystemApp && !fromTrustedStore && !isKnownOemApp

        // Surveillance permissions
        val grantedPermissions = pkg.requestedPermissions?.toList() ?: emptyList()
        val matchedSurveillancePerms = grantedPermissions.filter { it in SURVEILLANCE_PERMISSIONS }
        val matchedHighRiskPerms = grantedPermissions.filter { it in HIGH_RISK_PERMISSIONS }

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

        val embeddedComponentClasses = extractComponentClassNames(pkg, pkgDetail)
        val embeddedNativeLibs = extractNativeLibFileNames(appInfo)

        // WebAPK shell-manifest meta-data (#299). Targeted per-package read:
        // the bulk getInstalledPackages call deliberately omits GET_META_DATA
        // (Binder size pressure), and only org.chromium.webapk.* packages can
        // satisfy the WebAPK rules' selection anyway.
        var webapkScope: String? = null
        var webapkStartUrl: String? = null
        if (packageName.startsWith(WEBAPK_PACKAGE_PREFIX)) {
            @Suppress("TooGenericExceptionCaught", "SwallowedException")
            try {
                val metaData = pm.getApplicationInfo(
                    packageName, PackageManager.GET_META_DATA
                ).metaData
                webapkScope = metaData?.getString(WEBAPK_META_SCOPE)
                webapkStartUrl = metaData?.getString(WEBAPK_META_START_URL)
            } catch (e: Exception) {
                Log.w(
                    TAG,
                    "collectTelemetry: WebAPK meta-data read failed for $packageName: ${e.message}"
                )
            }
        }

        return AppTelemetry(
            packageName = packageName,
            appName = appName,
            certHash = certHash,
            certHashSha1 = certHashSha1,
            apkHash = apkHash,
            isSystemApp = isSystemApp,
            fromTrustedStore = fromTrustedStore,
            installer = installerPackage,
            isSideloaded = isSideloaded,
            isKnownOemApp = isKnownOemApp,
            permissions = (matchedSurveillancePerms + matchedHighRiskPerms)
                .map { it.substringAfterLast('.') },
            surveillancePermissionCount = matchedSurveillancePerms.size,
            hasAccessibilityService = hasAccessibilityService,
            hasDeviceAdmin = hasDeviceAdmin,
            knownAppCategory = knownApp?.category?.name,
            servicePermissions = servicePermissions,
            receiverPermissions = receiverPermissions,
            hasLauncherActivity = hasLauncherActivity,
            firstInstallTime = pkg.firstInstallTime,
            lastUpdateTime = pkg.lastUpdateTime,
            source = TelemetrySource.LIVE_SCAN,
            embeddedComponentClasses = embeddedComponentClasses,
            embeddedNativeLibs = embeddedNativeLibs,
            webapkScope = webapkScope,
            webapkStartUrl = webapkStartUrl,
        )
    }

    /**
     * Returns deduped, sorted class names from a PackageInfo's services,
     * receivers, activities, and providers arrays. Used downstream by SIGMA
     * rules that fingerprint embedded SDKs by class-name prefix. See
     * spec `docs/superpowers/specs/2026-05-17-data-broker-sdk-scanner-design.md`.
     *
     * Output is capped at [MAX_COMPONENTS_PER_APP] to bound memory against
     * pathological/malicious manifests. Sort happens BEFORE truncation so
     * the truncated subset is the lexicographically-first N — stable under
     * small manifest perturbations (a manifest gaining one component
     * doesn't shift the survival window arbitrarily).
     */
    internal fun extractComponentClassNames(
        primary: PackageInfo,
        fallback: PackageInfo? = null,
    ): List<String> {
        val out = LinkedHashSet<String>()
        val services   = primary.services   ?: fallback?.services
        val receivers  = primary.receivers  ?: fallback?.receivers
        val activities = primary.activities ?: fallback?.activities
        val providers  = primary.providers  ?: fallback?.providers
        services?.forEach   { it.name?.takeIf { n -> n.isNotBlank() }?.let { n -> out.add(n) } }
        receivers?.forEach  { it.name?.takeIf { n -> n.isNotBlank() }?.let { n -> out.add(n) } }
        activities?.forEach { it.name?.takeIf { n -> n.isNotBlank() }?.let { n -> out.add(n) } }
        providers?.forEach  { it.name?.takeIf { n -> n.isNotBlank() }?.let { n -> out.add(n) } }
        return out.asSequence().sorted().take(MAX_COMPONENTS_PER_APP).toList()
    }

    /**
     * Returns deduped, sorted leaf filenames of native libraries embedded
     * in the APK at [applicationInfo.publicSourceDir]. ABI prefix is stripped
     * so `lib/arm64-v8a/libxmode.so` and `lib/x86_64/libxmode.so` collapse
     * to a single `libxmode.so` entry. Output is capped at
     * [MAX_NATIVE_LIBS_PER_APP]. Sort happens BEFORE truncation so the
     * surviving subset is the lexicographically-first N (deterministic
     * under small APK perturbations). Failures (unreadable APK, corrupt
     * zip) are logged and produce an empty list — never thrown — so one
     * bad APK cannot abort the whole scan.
     */
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    internal fun extractNativeLibFileNames(applicationInfo: ApplicationInfo): List<String> {
        val path = applicationInfo.publicSourceDir ?: return emptyList()
        val out = LinkedHashSet<String>()
        try {
            ZipFile(path).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val name = entries.nextElement().name
                    if (name.startsWith("lib/") && name.endsWith(".so")) {
                        val leaf = name.substringAfterLast('/')
                        if (leaf.isNotBlank()) out.add(leaf)
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "extractNativeLibFileNames failed for $path: ${e.message}")
            return emptyList()
        }
        return out.asSequence().sorted().take(MAX_NATIVE_LIBS_PER_APP).toList()
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

    /**
     * Returns SHA-256 + SHA-1 of the first signing cert. SHA-1 is required to
     * match community feeds (stalkerware-indicators, MVT) that index by SHA-1,
     * per the Android ecosystem convention (apksigner prints SHA-1 by default).
     * Both hashes are of the same certificate bytes.
     *
     * Tripwire: if a 3rd algorithm is added (e.g. BLAKE3 64-hex collides with
     * SHA-256 by length), switch from per-algo AppTelemetry fields to
     * `Map<String, String>` keyed by algorithm and update rule 002 to iterate.
     */
    private fun extractCertHashes(packageInfo: android.content.pm.PackageInfo): CertHashes? {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.signingInfo?.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures
        }
        val cert = signatures?.firstOrNull() ?: return null
        val certBytes = cert.toByteArray()
        val sha256 = MessageDigest.getInstance("SHA-256").digest(certBytes)
            .joinToString("") { "%02x".format(it) }
        val sha1 = MessageDigest.getInstance("SHA-1").digest(certBytes)
            .joinToString("") { "%02x".format(it) }
        return CertHashes(sha256 = sha256, sha1 = sha1)
    }

    private data class CertHashes(val sha256: String, val sha1: String)

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
