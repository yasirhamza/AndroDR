package com.androdr.ui.permissions

import android.content.Context
import android.content.Intent
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
     * Checks whether `PACKAGE_USAGE_STATS` is currently granted to this app, through AppOps rather
     * than by catching the eventual `SecurityException` from `queryEvents()`. The one check is
     * [com.androdr.scanner.UsageAccess.isGranted], shared with the live scan's usage collection.
     */
    fun isGranted(context: Context): Boolean = com.androdr.scanner.UsageAccess.isGranted(context)

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
