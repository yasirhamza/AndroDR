package com.androdr.ui.permissions

import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Process
import android.provider.Settings

/**
 * Helpers for detecting and requesting the `PACKAGE_USAGE_STATS` permission.
 *
 * Unlike normal runtime permissions, Usage Access is a "special access"
 * permission that **cannot be requested via the runtime permission dialog**.
 * The only thing an app can do is open the Usage Access settings page via
 * [Intent.ACTION_USAGE_ACCESS_SETTINGS][Settings.ACTION_USAGE_ACCESS_SETTINGS]
 * and let the user grant it by toggling a switch. Apps that need this
 * permission (Digital Wellbeing, screen-time apps, forensic tools) all do
 * the same dance: detect it's not granted, show a banner, deep-link to the
 * settings screen.
 *
 * Previously AndroDR declared the permission in the manifest, caught the
 * resulting `SecurityException` from `UsageStatsManager.queryEvents()` at
 * DEBUG level, and silently returned an empty list — meaning the forensic
 * timeline feature appeared completely broken to anyone who didn't already
 * know to dig into Settings > Apps > Special access > Usage access and
 * enable AndroDR. This helper fixes that by giving the UI a first-class
 * way to ask "is Usage Access granted?" and a one-liner to launch the
 * settings screen so the user can grant it.
 */
object UsageStatsPermission {

    /**
     * Checks whether `PACKAGE_USAGE_STATS` is currently granted to this app.
     *
     * The canonical way to detect this is via [AppOpsManager], not by
     * catching the eventual `SecurityException` from `queryEvents()`. Use
     * [AppOpsManager.unsafeCheckOpNoThrow] on API 29+ (the older
     * [AppOpsManager.checkOpNoThrow] was deprecated in Q). On API 26-28 the
     * deprecated overload is still the correct choice.
     */
    fun isGranted(context: Context): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
            ?: return false
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    /**
     * Opens the system Usage Access settings screen. The user will see a
     * list of apps and toggles; tapping AndroDR's entry grants the
     * permission. Returns `true` if the intent was successfully launched,
     * `false` if no activity was resolvable (rare — the settings screen is
     * part of the system image on every Android version we target).
     */
    fun openSettings(context: Context): Boolean {
        val intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).apply {
            // FLAG_ACTIVITY_NEW_TASK is required when launching an activity
            // from a non-Activity context (the AppContext Hilt provides).
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return try {
            context.startActivity(intent)
            true
        } catch (_: android.content.ActivityNotFoundException) {
            false
        }
    }
}
