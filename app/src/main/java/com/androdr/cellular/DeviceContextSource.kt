package com.androdr.cellular

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.content.Context
import android.location.LocationManager
import android.os.PowerManager
import android.telephony.ServiceState
import android.telephony.TelephonyManager
import com.androdr.data.model.CaptureContext
import com.androdr.data.model.CaptureOrigin
import com.androdr.data.model.ServiceContext

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

    /** The SIM's home operator; null when there is no SIM or it cannot be read. */
    fun sim(): SimIdentity?

    /** Registration state, roaming and the data bearer; every field null when unreadable. */
    fun service(): ServiceContext
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

    override fun sim(): SimIdentity? = runCatching {
        telephony?.let { SimIdentity.fromSimOperator(it.simOperator, it.simOperatorName) }
    }.getOrNull()

    /**
     * The registration side of the radio, which the cell list does not
     * carry: whether the UE is actually in service, whether it is roaming
     * (a mismatch between the serving PLMN and the SIM is expected then,
     * and the PLMN rule must not fire on it), and which bearer carries data.
     *
     * RegistrationFailed and BarringInfo, the two callbacks that would show
     * a rejected attach, need READ_PRECISE_PHONE_STATE and are out of reach
     * for an unprivileged app; this is the part of ServiceState that is not.
     */
    // READ_PHONE_STATE is a preflight condition for arming the monitor; a
    // refused read lands in runCatching and reads as "unknown".
    @SuppressLint("MissingPermission")
    override fun service(): ServiceContext {
        val tm = telephony ?: return ServiceContext()
        val state = runCatching { tm.serviceState }.getOrNull()
        return ServiceContext(
            state = state?.let { serviceStateName(it.state) },
            isRoaming = state?.roaming,
            dataNetworkType = runCatching { networkTypeName(tm.dataNetworkType) }.getOrNull(),
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

    private fun serviceStateName(value: Int): String = when (value) {
        ServiceState.STATE_IN_SERVICE -> "IN_SERVICE"
        ServiceState.STATE_OUT_OF_SERVICE -> "OUT_OF_SERVICE"
        ServiceState.STATE_EMERGENCY_ONLY -> "EMERGENCY_ONLY"
        ServiceState.STATE_POWER_OFF -> "POWER_OFF"
        else -> "UNKNOWN"
    }

    private fun networkTypeName(value: Int): String = NETWORK_TYPE_NAMES[value] ?: "UNKNOWN"

    private companion object {
        /** TelephonyManager.NETWORK_TYPE_* by value; the platform offers no public name lookup. */
        val NETWORK_TYPE_NAMES: Map<Int, String> = mapOf(
            TelephonyManager.NETWORK_TYPE_GPRS to "GPRS",
            TelephonyManager.NETWORK_TYPE_EDGE to "EDGE",
            TelephonyManager.NETWORK_TYPE_UMTS to "UMTS",
            TelephonyManager.NETWORK_TYPE_CDMA to "CDMA",
            TelephonyManager.NETWORK_TYPE_EVDO_0 to "EVDO_0",
            TelephonyManager.NETWORK_TYPE_EVDO_A to "EVDO_A",
            TelephonyManager.NETWORK_TYPE_1xRTT to "1xRTT",
            TelephonyManager.NETWORK_TYPE_HSDPA to "HSDPA",
            TelephonyManager.NETWORK_TYPE_HSUPA to "HSUPA",
            TelephonyManager.NETWORK_TYPE_HSPA to "HSPA",
            TelephonyManager.NETWORK_TYPE_IDEN to "IDEN",
            TelephonyManager.NETWORK_TYPE_EVDO_B to "EVDO_B",
            TelephonyManager.NETWORK_TYPE_LTE to "LTE",
            TelephonyManager.NETWORK_TYPE_EHRPD to "EHRPD",
            TelephonyManager.NETWORK_TYPE_HSPAP to "HSPAP",
            TelephonyManager.NETWORK_TYPE_GSM to "GSM",
            TelephonyManager.NETWORK_TYPE_TD_SCDMA to "TD_SCDMA",
            TelephonyManager.NETWORK_TYPE_IWLAN to "IWLAN",
            TelephonyManager.NETWORK_TYPE_NR to "NR",
        )
    }
}
