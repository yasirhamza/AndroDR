package com.androdr.privacy

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import androidx.core.content.pm.PackageInfoCompat
import com.androdr.privacy.DexPackageReader.ApkUnreadableException
import com.androdr.privacy.DexPackageReader.DexOutcome
import com.androdr.privacy.DexPackageReader.ReadBudget
import com.androdr.util.reportSafe
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

enum class InspectOutcome { INSPECTED, PARTIAL, COULD_NOT_INSPECT }

data class InstalledApp(
    val packageName: String,
    val versionCode: Long,
    val lastUpdateTime: Long,
    val appLabel: String,
    val isSystemApp: Boolean,
    /** Base APK followed by every split APK. */
    val apkPaths: List<String>,
    /**
     * `ApplicationInfo.FLAG_HAS_CODE`: the app declares code. When true and no APK holds a loaded dex, the code
     * was stored outside the APK (stripped into `oat/` as an odex) and was never read — unless the APK's folder
     * lists no `oat` at all, which proves a resource-only package (#452). Defaults to true, so an
     * app is never said to be free of trackers because a caller forgot to set it.
     */
    val hasCode: Boolean = true,
)

data class AppInspection(
    val app: InstalledApp,
    val packages: Set<String>,
    val outcome: InspectOutcome,
    val reason: String?,
)

interface AppInspector {
    /** Every installed app, sorted by package name. */
    fun installedApps(): List<InstalledApp>

    /** Unions the dex packages of [app]'s APKs under the one shared [budget]; never throws for APK content. */
    fun inspect(app: InstalledApp, budget: ReadBudget): AppInspection
}

@Singleton
class ApkPackageInspector @Inject constructor(
    @ApplicationContext private val context: Context,
) : AppInspector {

    override fun installedApps(): List<InstalledApp> {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val installed = pm.getInstalledPackages(0)
        return installed.mapNotNull { toInstalledApp(it) }.sortedBy { it.packageName }
    }

    private fun toInstalledApp(pi: PackageInfo): InstalledApp? {
        val info = pi.applicationInfo ?: return null
        val paths = ArrayList<String>()
        info.sourceDir?.let { paths.add(it) }
        info.splitSourceDirs?.forEach { if (it != null) paths.add(it) }
        val label = try {
            context.packageManager.getApplicationLabel(info).toString()
        } catch (_: RuntimeException) {
            pi.packageName
        }
        return InstalledApp(
            packageName = pi.packageName,
            versionCode = PackageInfoCompat.getLongVersionCode(pi),
            lastUpdateTime = pi.lastUpdateTime,
            appLabel = label,
            isSystemApp = info.flags and ApplicationInfo.FLAG_SYSTEM != 0,
            apkPaths = paths,
            hasCode = info.flags and ApplicationInfo.FLAG_HAS_CODE != 0,
        )
    }

    override fun inspect(app: InstalledApp, budget: ReadBudget): AppInspection {
        val packages = LinkedHashSet<String>()
        val notes = LinkedHashSet<String>()
        var readable = 0
        var unreadable = 0
        var timedOut = false
        var anyDex = false
        for (path in app.apkPaths) {
            try {
                val result = DexPackageReader.read(File(path), budget)
                readable++
                anyDex = anyDex || result.hasDex
                packages.addAll(result.packages)
                describe(result, notes)
                timedOut = timedOut || result.dexOutcomes.values.any { it == DexOutcome.TIME_LIMIT }
            } catch (_: ApkUnreadableException) {
                unreadable++
            }
        }
        if (unreadable > 0) notes.add("$unreadable apk unreadable")
        // Declared code but no loaded dex in any APK read: the code was stripped into oat/ and never read, so nothing
        // may be concluded — unless the app provably has no code at all (#452).
        val codeOutside = app.hasCode && readable > 0 && !anyDex && !provablyCodeless(app)
        return conclude(app, packages, notes, Reading(readable, timedOut, codeOutside))
    }

    /**
     * `android:hasCode` defaults to true, so resource-only packages (overlays, `*-res` APKs) declare code they do
     * not have. A system app whose dex was stripped from its APK keeps the precompiled code in an `oat/` folder
     * beside it; with no dex in the APK and no `oat` there, there is no code anywhere. Only a folder that can be
     * listed proves the absence: an unlistable one keeps "code stored outside the APK".
     */
    private fun provablyCodeless(app: InstalledApp): Boolean {
        val base = app.apkPaths.firstOrNull() ?: return false
        val siblings = File(base).parentFile?.list() ?: return false
        return OAT_DIR !in siblings
    }

    private class Reading(val readable: Int, val timedOut: Boolean, val codeOutside: Boolean)

    private fun conclude(app: InstalledApp, packages: Set<String>, notes: Set<String>, r: Reading): AppInspection {
        val outcome = when {
            r.readable == 0 -> InspectOutcome.COULD_NOT_INSPECT
            r.codeOutside -> InspectOutcome.COULD_NOT_INSPECT
            r.timedOut && packages.isEmpty() -> InspectOutcome.COULD_NOT_INSPECT
            notes.isNotEmpty() -> InspectOutcome.PARTIAL
            else -> InspectOutcome.INSPECTED
        }
        val reason = when {
            app.apkPaths.isEmpty() -> "no apk"
            outcome == InspectOutcome.INSPECTED -> null
            r.readable == 0 -> "apk unreadable"
            r.codeOutside && notes.isEmpty() -> CODE_OUTSIDE_APK
            else -> reportSafe(notes.joinToString("; "), REASON_MAX)
        }
        return AppInspection(app, packages, outcome, reason)
    }

    private fun describe(result: DexPackageReader.Result, notes: MutableSet<String>) {
        val skipped = result.dexOutcomes.filterValues { it == DexOutcome.SKIPPED_OVER_CAP }.keys
        val malformed = result.dexOutcomes.filterValues { it == DexOutcome.MALFORMED }.keys
        if (skipped.isNotEmpty()) notes.add("skipped ${skipped.joinToString(",")}")
        if (malformed.isNotEmpty()) notes.add("malformed ${malformed.joinToString(",")}")
        if (result.packageCapHit) notes.add("package cap")
        if (result.dexOutcomes.values.any { it == DexOutcome.TIME_LIMIT }) notes.add("time limit")
    }

    companion object {
        private const val REASON_MAX = 160
        private const val OAT_DIR = "oat"

        /** The reason for an app that declares code but has no loaded dex in any of its APKs. */
        const val CODE_OUTSIDE_APK = "code stored outside the APK"
    }
}
