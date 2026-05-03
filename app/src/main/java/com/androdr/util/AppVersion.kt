package com.androdr.util

import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.pm.PackageInfoCompat

data class AppVersion(val name: String, val code: Long)

/**
 * Reads versionName and longVersionCode from the installed APK's manifest at runtime.
 * Avoids BuildConfig: Kotlin inlines `BuildConfig.VERSION_NAME`/`VERSION_CODE` as
 * compile-time constants, and the Gradle build cache can serve those constants stale
 * when surrounding source files don't change but the build metadata does.
 */
fun Context.appVersion(): AppVersion = try {
    val info = packageManager.getPackageInfo(packageName, 0)
    AppVersion(
        name = info.versionName.orEmpty(),
        code = PackageInfoCompat.getLongVersionCode(info),
    )
} catch (_: PackageManager.NameNotFoundException) {
    AppVersion(name = "", code = 0L)
}
