package com.androdr.privacy

import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.pm.PackageInfoCompat
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/** Installed version code per package, to match stored privacy results to what is on the device now. */
@Singleton
class InstalledVersions @Inject constructor(@ApplicationContext private val ctx: Context) {

    /** One batch per call. A package that is not installed (or unreadable) is absent from the result. */
    suspend fun versionCodes(pkgs: Collection<String>): Map<String, Long> = withContext(Dispatchers.IO) {
        val pm = ctx.packageManager
        pkgs.distinct().mapNotNull { pkg ->
            try {
                pkg to PackageInfoCompat.getLongVersionCode(pm.getPackageInfo(pkg, 0))
            } catch (_: PackageManager.NameNotFoundException) {
                null
            }
        }.toMap()
    }
}
