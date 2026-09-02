package com.androdr.cellular

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.content.Context
import android.location.LocationManager
import android.os.PowerManager
import android.telephony.TelephonyManager
import com.androdr.data.model.CaptureContext
import com.androdr.data.model.CaptureOrigin

/**
 * The circumstances of a capture, read from the platform alongside the cell
 * list. Everything here is best-effort and null means "could not tell":
 * a context read must never stop a radio observation from being recorded.
 *
 * An interface so the monitor's handle() path is testable without a device;
 * [PlatformDeviceContext] is the only production implementation.
 */
interface DeviceContextSource {
    fun capture(origin: CaptureOrigin, rawRecordCount: Int): CaptureContext

    /** Movement over the churn window and how fresh the fix behind it is. */
    fun movement(now: Long): Movement
}

/** Both null when the device has no usable fix; see [LocationTrail]. */
data class Movement(val movedMetersLast5m: Int? = null, val fixAgeSeconds: Int? = null)

/**
 * Reads from ActivityManager, PowerManager, TelephonyManager and the
 * passive location provider.
 *
 * Why the first three: the 0.9.0.638 report showed six "no neighbours"
 * findings that could not be told apart from an idle radio. A UE in
 * RRC_IDLE with a strong serving cell measures no neighbours (3GPP 36.304),
 * and the screen being interactive is the best unprivileged proxy for
 * connected mode; an app without a visible activity may also be handed a
 * truncated list. Both are facts about the READ, not the radio, and a rule
 * needs them to filter.
 *
 * Why passive location only: the monitor must cost no battery when the
 * radio is idle, so it never requests a fix — it borrows whichever one some
 * other app most recently obtained. That fix may be stale, which is why its
 * age is emitted next to the distance.
 */
class PlatformDeviceContext(
    private val context: Context,
    private val trail: LocationTrail = LocationTrail(),
) : DeviceContextSource {

    private val telephony: TelephonyManager?
        get() = context.getSystemService(TelephonyManager::class.java)

    override fun capture(origin: CaptureOrigin, rawRecordCount: Int): CaptureContext = CaptureContext(
        origin = origin,
        appForeground = runCatching { appHasVisibleActivity() }.getOrNull(),
        screenInteractive = runCatching {
            context.getSystemService(PowerManager::class.java)?.isInteractive
        }.getOrNull(),
        dataActivity = runCatching { telephony?.dataActivity?.let(::dataActivityName) }.getOrNull(),
        rawRecordCount = rawRecordCount,
    )

    /**
     * PRIVACY: the coordinates go into [trail] and nowhere else. They are not
     * logged (a passive fix in logcat would be the very location trail the
     * cell-identity redaction exists to prevent), not emitted and not
     * persisted; only the derived distance and the fix age leave this class.
     */
    // The monitor only arms once ACCESS_FINE_LOCATION is granted (preflight);
    // a refused read lands in runCatching and reads as "no fix".
    @SuppressLint("MissingPermission")
    override fun movement(now: Long): Movement {
        runCatching {
            context.getSystemService(LocationManager::class.java)
                ?.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER)
        }.getOrNull()?.let { trail.record(it.latitude, it.longitude, it.time) }
        return Movement(
            movedMetersLast5m = trail.movedMetersLast(RadioStateStore.DEFAULT_WINDOW_MILLIS, now),
            fixAgeSeconds = trail.fixAgeSeconds(now),
        )
    }

    /**
     * The monitor lives in a foreground service, so process importance is
     * FOREGROUND_SERVICE (125) whenever no activity is showing; only
     * FOREGROUND (100) and VISIBLE (200) mean the user can see the app.
     */
    private fun appHasVisibleActivity(): Boolean {
        val info = ActivityManager.RunningAppProcessInfo()
        ActivityManager.getMyMemoryState(info)
        return info.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND ||
            info.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE
    }

    private fun dataActivityName(value: Int): String = when (value) {
        TelephonyManager.DATA_ACTIVITY_NONE -> "NONE"
        TelephonyManager.DATA_ACTIVITY_IN -> "IN"
        TelephonyManager.DATA_ACTIVITY_OUT -> "OUT"
        TelephonyManager.DATA_ACTIVITY_INOUT -> "INOUT"
        TelephonyManager.DATA_ACTIVITY_DORMANT -> "DORMANT"
        else -> "UNKNOWN"
    }
}
