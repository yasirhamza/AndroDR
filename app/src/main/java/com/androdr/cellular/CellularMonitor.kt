package com.androdr.cellular

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoWcdma
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.SigmaRuleEngine

/**
 * Tier 1 radio telemetry: the live caller that makes `cellular_monitor` rules
 * able to fire at all.
 *
 * Event-driven by design. A TelephonyCallback registered inside the
 * DnsVpnService foreground context delivers cell and RAT changes as they
 * happen, so transitions are observed directly rather than inferred from
 * samples — which also sidesteps Android's background poll throttling and
 * costs no battery when the radio is idle.
 *
 * Inert unless BOTH permissions are granted and the platform is API 31+.
 * Research branch only: these permissions are never declared on main.
 *
 * FOREGROUND GATING — measured on SM-F916B / Android 13, 2026-08-22, and the
 * single most important constraint on this whole feature:
 *
 *  - Called with location permission but the app in the BACKGROUND,
 *    getAllCellInfo() returns an EMPTY list. Not an error, not stale data —
 *    silently nothing.
 *  - Called with NO location permission it throws
 *    SecurityException("Not allowed to access cell info").
 *  - With an activity visible it returns the full list (14 records: 1 serving
 *    plus 13 neighbours).
 *
 * So a background caller cannot distinguish "no cells nearby" from "not
 * allowed to look" — which is why DnsVpnService declares
 * foregroundServiceType="specialUse|location" plus
 * FOREGROUND_SERVICE_LOCATION. A specialUse-only service does not confer
 * location access on Android 10+.
 *
 * UNVERIFIED: whether TelephonyCallback deliveries inside that
 * location-typed foreground service actually carry a populated list. That
 * needs a VPN session on the device to confirm, and until it is confirmed
 * this feature cannot be assumed to work in the field.
 */
class CellularMonitor(
    private val context: Context,
    private val engine: SigmaRuleEngine,
    private val store: RadioStateStore = RadioStateStore(),
) {
    private var callback: TelephonyCallback? = null

    private fun hasPermissions(): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) ==
            PackageManager.PERMISSION_GRANTED

    @RequiresApi(Build.VERSION_CODES.S)
    private inner class Callback : TelephonyCallback(), TelephonyCallback.CellInfoListener {
        override fun onCellInfoChanged(cellInfo: MutableList<CellInfo>) = handle(cellInfo)
    }

    fun start() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            Log.i(TAG, "TelephonyCallback requires API 31+; cellular monitor inert")
            return
        }
        if (!hasPermissions()) {
            Log.i(TAG, "ACCESS_FINE_LOCATION / READ_PHONE_STATE not granted; cellular monitor inert")
            return
        }
        val tm = context.getSystemService(TelephonyManager::class.java)
        if (tm == null) {
            Log.w(TAG, "No TelephonyManager; cellular monitor inert")
            return
        }
        val cb = Callback()
        callback = cb
        tm.registerTelephonyCallback(context.mainExecutor, cb)
        Log.i(TAG, "Cellular monitor started")
    }

    fun stop() {
        val cb = callback ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            context.getSystemService(TelephonyManager::class.java)?.unregisterTelephonyCallback(cb)
        }
        callback = null
        Log.i(TAG, "Cellular monitor stopped")
    }

    internal fun handle(cellInfo: List<CellInfo>) {
        val serving = cellInfo.firstOrNull { it.isRegistered } ?: return
        val snapshot = toSnapshot(serving, cellInfo, System.currentTimeMillis())
        runCatching { engine.evaluateCellular(listOf(snapshot)) }
            .onSuccess { findings ->
                findings.filter { it.triggered }.forEach {
                    Log.w(TAG, "Cellular finding: ${it.ruleId}")
                }
            }
            .onFailure { Log.e(TAG, "evaluateCellular failed: ${it.message}") }
    }

    /** Android reports unavailable integers as Integer.MAX_VALUE. */
    private fun sentinel(value: Int): Int? = if (value == Int.MAX_VALUE) null else value

    @SuppressLint("NewApi")
    internal fun toSnapshot(serving: CellInfo, all: List<CellInfo>, now: Long): CellularSnapshot {
        val rat = when (serving) {
            is CellInfoNr -> "NR"
            is CellInfoLte -> "LTE"
            is CellInfoWcdma -> "UMTS"
            is CellInfoGsm -> "GSM"
            else -> "UNKNOWN"
        }
        val lte = serving as? CellInfoLte
        val id = lte?.cellIdentity
        val tac = id?.tac?.let { sentinel(it) }
        val derived = store.record(tac, rat, now)
        val servingRsrp = lte?.cellSignalStrength?.rsrp?.let { sentinel(it) }
        val neighbours = all.filter { !it.isRegistered }
        val maxNeighborRsrp = neighbours.filterIsInstance<CellInfoLte>()
            .mapNotNull { sentinel(it.cellSignalStrength.rsrp) }
            .maxOrNull()
        val apiR = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

        return CellularSnapshot(
            mcc = id?.mccString,
            mnc = id?.mncString,
            tac = tac,
            ci = id?.ci?.let { sentinel(it) }?.toLong(),
            pci = id?.pci?.let { sentinel(it) },
            earfcn = id?.earfcn?.let { sentinel(it) },
            bands = if (apiR) id?.bands?.toList().orEmpty() else emptyList(),
            bandwidthKhz = if (apiR) id?.bandwidth?.let { sentinel(it) } else null,
            rat = rat,
            operatorAlphaLong = id?.operatorAlphaLong?.toString(),
            operatorAlphaShort = id?.operatorAlphaShort?.toString(),
            additionalPlmns = if (apiR) id?.additionalPlmns?.toList().orEmpty() else emptyList(),
            neighborCount = neighbours.size,
            servingRsrp = servingRsrp,
            isRegistered = true,
            capturedAt = now,
            source = TelemetrySource.LIVE_SCAN,
            previousTac = derived.previousTac,
            previousRat = derived.previousRat,
            tacChanged = derived.tacChanged,
            ratChanged = derived.ratChanged,
            tacChangesLast5m = derived.tacChangesLast5m,
            servingMinusMaxNeighborRsrpDb =
                if (servingRsrp != null && maxNeighborRsrp != null) {
                    servingRsrp - maxNeighborRsrp
                } else {
                    null
                },
            locationMovedMLast5m = null,
        )
    }

    private companion object {
        const val TAG = "CellularMonitor"
    }
}
