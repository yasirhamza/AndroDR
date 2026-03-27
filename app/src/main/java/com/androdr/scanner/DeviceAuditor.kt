package com.androdr.scanner

import android.annotation.SuppressLint
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import android.util.Log
import com.androdr.data.model.DeviceTelemetry
import com.androdr.ioc.CveDatabase
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
    @ApplicationContext private val context: Context,
    private val cveDatabase: CveDatabase
) {

    private companion object {
        private const val TAG = "DeviceAuditor"
    }

    /**
     * The most recent known security patch date used as the reference point for
     * staleness checks. Update this value when a newer patch series is released.
     */
    private val latestKnownPatch = "2025-03-01"

    /**
     * Collects device posture telemetry and returns structured [DeviceTelemetry]
     * entries for the SIGMA rule engine. Each entry carries both its own trigger
     * state and a snapshot of all posture fields so that rules can correlate
     * multiple signals.
     */
    @Suppress("LongMethod")
    suspend fun collectTelemetry(): List<DeviceTelemetry> = withContext(Dispatchers.IO) {
        val cr = context.contentResolver

        // ── Gather all device posture check values ────────────────────────────
        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        val adbEnabled = try {
            Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (e: Exception) {
            Log.w(TAG, "collectTelemetry: ADB_ENABLED setting read failed: ${e.message}")
            false
        }

        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        val devOptionsEnabled = try {
            Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        } catch (e: Exception) {
            Log.w(TAG, "collectTelemetry: DEVELOPMENT_SETTINGS_ENABLED setting read failed: ${e.message}")
            false
        }

        val unknownSourcesEnabled =
            !context.packageManager.hasSystemFeature("android.software.verified_boot")

        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        val noScreenLock = try {
            val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            km?.isDeviceSecure?.not() ?: true
        } catch (e: Exception) {
            Log.w(TAG, "collectTelemetry: screen lock state check failed: ${e.message}")
            false
        }

        val patchStr = Build.VERSION.SECURITY_PATCH ?: ""
        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        val patchAgeDays = try {
            if (patchStr.isBlank()) {
                0
            } else {
                val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
                val patchDate = LocalDate.parse(patchStr, formatter)
                val referenceDate = LocalDate.parse(latestKnownPatch, formatter)
                ChronoUnit.DAYS.between(patchDate, referenceDate).toInt()
            }
        } catch (e: Exception) {
            Log.w(TAG, "collectTelemetry: security patch level parse failed: ${e.message}")
            0
        }

        val unpatchedCves = cveDatabase.getUnpatchedCves(patchStr)

        val bootloaderUnlocked = isBootloaderUnlocked()

        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        val wifiAdbEnabled = try {
            Settings.Global.getInt(cr, "adb_wifi_enabled", 0) == 1
        } catch (e: Exception) {
            Log.w(TAG, "collectTelemetry: adb_wifi_enabled setting read failed: ${e.message}")
            false
        }

        val screenLockEnabled = !noScreenLock

        // Single telemetry record with all device posture fields — SIGMA rules
        // evaluate against this one record, each rule matching its own field(s).
        listOf(DeviceTelemetry(
            checkId = "device_posture",
            isTriggered = false,
            adbEnabled = adbEnabled,
            devOptionsEnabled = devOptionsEnabled,
            unknownSourcesEnabled = unknownSourcesEnabled,
            screenLockEnabled = screenLockEnabled,
            patchLevel = patchStr,
            patchAgeDays = patchAgeDays,
            bootloaderUnlocked = bootloaderUnlocked,
            wifiAdbEnabled = wifiAdbEnabled,
            unpatchedCveCount = unpatchedCves.size
        ))
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
