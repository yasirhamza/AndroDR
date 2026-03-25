package com.androdr.scanner

import android.annotation.SuppressLint
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import android.util.Log
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

    private companion object {
        private const val TAG = "DeviceAuditor"
    }

    /**
     * The most recent known security patch date used as the reference point for
     * staleness checks. Update this value when a newer patch series is released.
     */
    private val latestKnownPatch = "2025-03-01"

    /** Patch levels older than this many days are considered stale. */
    private val maxPatchAgeDays = 90L

    @Suppress("LongMethod") // Device audit checks 7 independent security properties in sequence;
    // each check is a small self-contained block — splitting would gain no readability benefit.
    suspend fun audit(): List<DeviceFlag> = withContext(Dispatchers.IO) {
        val cr = context.contentResolver
        val flags = mutableListOf<DeviceFlag>()

        // ── 1. USB ADB enabled ────────────────────────────────────────────────
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // Settings.Global.getInt can
        // throw SecurityException on locked-down device policies; default false is safe.
        val adbEnabled = try {
            Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (e: Exception) {
            Log.w(TAG, "DeviceAuditor: ADB_ENABLED setting read failed: ${e.message}")
            false
        }
        flags.add(DeviceFlag.adbEnabled(adbEnabled))

        // ── 2. Developer Options enabled ──────────────────────────────────────
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // Same rationale as adbEnabled
        val devOptionsEnabled = try {
            Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        } catch (e: Exception) {
            Log.w(TAG, "DeviceAuditor: DEVELOPMENT_SETTINGS_ENABLED setting read failed: ${e.message}")
            false
        }
        flags.add(DeviceFlag.devOptionsEnabled(devOptionsEnabled))

        // ── 3. Install from unknown sources ───────────────────────────────────
        // minSdk = 26 (O) so the per-app unknown-sources permission model always applies.
        // We cannot reliably read the per-package allow-unknown-sources state without a
        // system permission, so we approximate via Verified Boot feature absence.
        val unknownSources =
            // On API 26+ we cannot reliably read per-package allow-unknown-sources state
            // without holding a system permission. Instead, check whether the device
            // advertises Verified Boot support; its absence suggests a more permissive
            // environment. This is an approximation only.
            !context.packageManager.hasSystemFeature("android.software.verified_boot")
        flags.add(DeviceFlag.unknownSources(unknownSources))

        // ── 4. Screen lock ────────────────────────────────────────────────────
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // getSystemService and
        // isDeviceSecure can throw on emulators or restricted profiles; false = assume secured.
        val noScreenLock = try {
            val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            // isDeviceSecure returns true if a PIN, password, pattern, or biometric is set.
            km?.isDeviceSecure?.not() ?: true
        } catch (e: Exception) {
            Log.w(TAG, "DeviceAuditor: screen lock state check failed: ${e.message}")
            false
        }
        flags.add(DeviceFlag.noScreenLock(noScreenLock))

        // ── 5. Security patch staleness ───────────────────────────────────────
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // DateTimeParseException or
        // other RuntimeExceptions if the OEM encodes a non-standard patch string; treat as stale.
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
            Log.w(TAG, "DeviceAuditor: security patch level parse failed: ${e.message}")
            true // Parse failure — treat as stale
        }
        flags.add(DeviceFlag.stalePatchLevel(stalePatch))

        // ── 6. Bootloader lock state ──────────────────────────────────────────
        val bootloaderUnlocked = isBootloaderUnlocked()
        flags.add(DeviceFlag.bootloaderUnlocked(bootloaderUnlocked))

        // ── 7. Wireless ADB (ADB over Wi-Fi) ─────────────────────────────────
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // Same rationale as adbEnabled
        val wifiAdbEnabled = try {
            Settings.Global.getInt(cr, "adb_wifi_enabled", 0) == 1
        } catch (e: Exception) {
            Log.w(TAG, "DeviceAuditor: adb_wifi_enabled setting read failed: ${e.message}")
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
    @Suppress("ReturnCount") // Two independent detection strategies each require an early return;
    // merging them into one return path would obscure the fallback logic between strategies.
    // PrivateApi: Reflecting android.os.SystemProperties is the only way to read
    // ro.boot.verifiedbootstate from a non-system app; this is an intentional EDR capability.
    // The catch block handles cases where reflection is blocked, making it safe to use.
    @SuppressLint("PrivateApi")
    private fun isBootloaderUnlocked(): Boolean {
        // Strategy 1: reflect into SystemProperties
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // Reflection can throw any
        // exception when blocked by device policy or missing class; fall through to strategy 2.
        try {
            val systemPropertiesClass = Class.forName("android.os.SystemProperties")
            val getMethod = systemPropertiesClass.getMethod("get", String::class.java, String::class.java)
            val verifiedBootState = getMethod.invoke(null, "ro.boot.verifiedbootstate", "") as? String
            if (!verifiedBootState.isNullOrBlank()) {
                return verifiedBootState.lowercase() == "orange"
            }
        } catch (e: Exception) {
            Log.w(TAG, "DeviceAuditor: SystemProperties reflection blocked, falling through: ${e.message}")
            // Reflection blocked on this device/API level — fall through
        }

        // Strategy 2: parse Build.BOOTLOADER string (OEM-specific heuristic)
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // Build.BOOTLOADER is OEM
        // defined; some ROMs throw on access; returning false = assume locked is safe default.
        return try {
            val bootloader = Build.BOOTLOADER ?: return false
            // Some OEMs include "unlocked" or "U" in the string when the bootloader is open.
            bootloader.lowercase().contains("unlocked") || bootloader.lowercase().contains("-u-")
        } catch (e: Exception) {
            Log.w(TAG, "DeviceAuditor: bootloader lock state check failed: ${e.message}")
            false
        }
    }
}
