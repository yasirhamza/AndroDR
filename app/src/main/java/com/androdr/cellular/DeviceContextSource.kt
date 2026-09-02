package com.androdr.cellular

import android.app.ActivityManager
import android.content.Context
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
}

/**
 * Reads from ActivityManager, PowerManager and TelephonyManager.
 *
 * Why these three: the 0.9.0.638 report showed six "no neighbours" findings
 * that could not be told apart from an idle radio. A UE in RRC_IDLE with a
 * strong serving cell measures no neighbours (3GPP 36.304), and the screen
 * being interactive is the best unprivileged proxy for connected mode; an
 * app without a visible activity may also be handed a truncated list. Both
 * are facts about the READ, not the radio, and a rule needs them to filter.
 */
class PlatformDeviceContext(private val context: Context) : DeviceContextSource {

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
