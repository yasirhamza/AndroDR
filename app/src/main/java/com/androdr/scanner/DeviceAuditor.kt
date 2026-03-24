package com.androdr.scanner

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.androdr.data.model.DeviceFlag
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DeviceAuditor @Inject constructor(
    @ApplicationContext private val context: Context
) {

    /**
     * The most recent known security patch date used as the reference point for
     * staleness checks. Update this value when a newer patch series is released.
     */
    private val latestKnownPatch = "2025-03-01"

    /** Patch levels older than this many days are considered stale. */
    private val maxPatchAgeDays = 90L

    suspend fun audit(): List<DeviceFlag> = withContext(Dispatchers.IO) {
        val cr = context.contentResolver
        val flags = mutableListOf<DeviceFlag>()

        // ── 1. USB ADB enabled ────────────────────────────────────────────────
        val adbEnabled = try {
            Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (e: Exception) {
            false
        }
        flags.add(DeviceFlag.adbEnabled(adbEnabled))

        // ── 2. Developer Options enabled ──────────────────────────────────────
        val devOptionsEnabled = try {
            Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        } catch (e: Exception) {
            false
        }
        flags.add(DeviceFlag.devOptionsEnabled(devOptionsEnabled))

        // ── 3. Install from unknown sources ───────────────────────────────────
        // On API 26+ the permission is per-app (no global setting); we approximate by
        // checking the FEATURE_VERIFIED_BOOT feature absence as a signal that the device
        // environment is less controlled. For API < 26 we read the legacy global setting.
        val unknownSources = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            try {
                Settings.Secure.getInt(cr, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
            } catch (e: Exception) {
                false
            }
        } else {
            // On API 26+ we cannot reliably read per-package allow-unknown-sources state
            // without holding a system permission. Instead, check whether the device
            // advertises Verified Boot support; its absence suggests a more permissive
            // environment. This is an approximation only.
            !context.packageManager.hasSystemFeature("android.software.verified_boot")
        }
        flags.add(DeviceFlag.unknownSources(unknownSources))

        // ── 4. Screen lock ────────────────────────────────────────────────────
        val noScreenLock = try {
            val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            // isDeviceSecure returns true if a PIN, password, pattern, or biometric is set.
            km?.isDeviceSecure?.not() ?: true
        } catch (e: Exception) {
            false
        }
        flags.add(DeviceFlag.noScreenLock(noScreenLock))

        // ── 5. Security patch staleness ───────────────────────────────────────
        val stalePatch = try {
            val patchStr = Build.VERSION.SECURITY_PATCH // "YYYY-MM-DD"
            if (patchStr.isNullOrBlank()) {
                true // Cannot determine patch level — treat as stale
            } else {
                val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
                val patchDate = LocalDate.parse(patchStr, formatter)
                val referenceDate = LocalDate.parse(latestKnownPatch, formatter)
                ChronoUnit.DAYS.between(patchDate, referenceDate) > maxPatchAgeDays
            }
        } catch (e: Exception) {
            true // Parse failure — treat as stale
        }
        flags.add(DeviceFlag.stalePatchLevel(stalePatch))

        // ── 6. Bootloader lock state ──────────────────────────────────────────
        val bootloaderUnlocked = isBootloaderUnlocked()
        flags.add(DeviceFlag.bootloaderUnlocked(bootloaderUnlocked))

        // ── 7. Wireless ADB (ADB over Wi-Fi) ─────────────────────────────────
        val wifiAdbEnabled = try {
            Settings.Global.getInt(cr, "adb_wifi_enabled", 0) == 1
        } catch (e: Exception) {
            false
        }
        flags.add(DeviceFlag.wifiAdbEnabled(wifiAdbEnabled))

        flags.toList()
    }

    /**
     * Attempts to determine whether the bootloader is unlocked via two strategies:
     *
     * 1. Reading the `ro.boot.verifiedbootstate` system property via reflection
     *    (values: "green" = locked + verified, "yellow" = locked + self-signed,
     *     "orange" = unlocked, "red" = failed verification).
     * 2. Falling back to [Build.BOOTLOADER] which on some OEMs encodes the lock state.
     *
     * Returns `true` if the bootloader appears unlocked; `false` if locked or unknown.
     */
    private fun isBootloaderUnlocked(): Boolean {
        // Strategy 1: reflect into SystemProperties
        try {
            val systemPropertiesClass = Class.forName("android.os.SystemProperties")
            val getMethod = systemPropertiesClass.getMethod("get", String::class.java, String::class.java)
            val verifiedBootState = getMethod.invoke(null, "ro.boot.verifiedbootstate", "") as? String
            if (!verifiedBootState.isNullOrBlank()) {
                return verifiedBootState.lowercase() == "orange"
            }
        } catch (e: Exception) {
            // Reflection blocked on this device/API level — fall through
        }

        // Strategy 2: parse Build.BOOTLOADER string (OEM-specific heuristic)
        return try {
            val bootloader = Build.BOOTLOADER ?: return false
            // Some OEMs include "unlocked" or "U" in the string when the bootloader is open.
            bootloader.lowercase().contains("unlocked") || bootloader.lowercase().contains("-u-")
        } catch (e: Exception) {
            false
        }
    }
}
