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
        )
    }

    override fun inspect(app: InstalledApp, budget: ReadBudget): AppInspection {
        val packages = LinkedHashSet<String>()
        val notes = LinkedHashSet<String>()
        var readable = 0
        var unreadable = 0
        var timedOut = false
        for (path in app.apkPaths) {
            try {
                val result = DexPackageReader.read(File(path), budget)
                readable++
                packages.addAll(result.packages)
                describe(result, notes)
                timedOut = timedOut || result.dexOutcomes.values.any { it == DexOutcome.TIME_LIMIT }
            } catch (_: ApkUnreadableException) {
                unreadable++
            }
        }
        if (unreadable > 0) notes.add("$unreadable apk unreadable")
        return conclude(app, packages, notes, readable, timedOut)
    }

    private fun conclude(
        app: InstalledApp,
        packages: Set<String>,
        notes: Set<String>,
        readable: Int,
        timedOut: Boolean,
    ): AppInspection {
        val outcome = when {
            readable == 0 -> InspectOutcome.COULD_NOT_INSPECT
            timedOut && packages.isEmpty() -> InspectOutcome.COULD_NOT_INSPECT
            notes.isNotEmpty() -> InspectOutcome.PARTIAL
            else -> InspectOutcome.INSPECTED
        }
        val reason = when {
            app.apkPaths.isEmpty() -> "no apk"
            outcome == InspectOutcome.INSPECTED -> null
            readable == 0 -> "apk unreadable"
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

    private companion object {
        const val REASON_MAX = 160
    }
}
