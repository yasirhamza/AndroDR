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
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.repo.ScanRepository
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

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
    private val repository: ScanRepository,
    private val scope: CoroutineScope,
    private val store: RadioStateStore = RadioStateStore(),
) {
    private var callback: TelephonyCallback? = null

    private fun hasPermissions(): Boolean = hasRequiredPermissions(context)

    @RequiresApi(Build.VERSION_CODES.S)
    private inner class Callback : TelephonyCallback(), TelephonyCallback.CellInfoListener {
        override fun onCellInfoChanged(cellInfo: MutableList<CellInfo>) = handle(cellInfo)
    }

    fun start() {
        // Idempotent: re-arming after the user grants location must not
        // register a second callback on top of a live one.
        if (callback != null) return
        val tm = preflight() ?: return
        // preflight() already rejects below API 31, but lint cannot see through
        // it. Kept as a real check rather than a suppression: the arming code
        // genuinely must not run on an older platform.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) arm(tm)
    }

    @RequiresApi(Build.VERSION_CODES.S)
    private fun arm(tm: TelephonyManager) {
        val cb = Callback()
        callback = cb
        tm.registerTelephonyCallback(context.mainExecutor, cb)
        Log.i(TAG, "Cellular monitor started")
        recordSessionStart()
        primeFromCurrentState(tm)
    }

    /**
     * Checks everything the monitor needs, recording WHICH requirement failed.
     *
     * Collapsed into one place because each of these conditions leaves the
     * monitor silently inert, and the UI has to be able to tell them apart —
     * "the VPN is off" and "the platform refused the read" look identical
     * otherwise.
     */
    private fun preflight(): TelephonyManager? {
        val blocked = when {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.S ->
                CellularState.Status.UNSUPPORTED_API to
                    "TelephonyCallback requires API 31+"
            !hasPermissions() ->
                CellularState.Status.MISSING_PERMISSION to
                    "ACCESS_FINE_LOCATION / READ_PHONE_STATE not granted"
            else -> null
        }
        if (blocked != null) {
            Log.i(TAG, "${blocked.second}; cellular monitor inert")
            CellularState.setStatus(blocked.first)
            return null
        }
        val tm = context.getSystemService(TelephonyManager::class.java)
        if (tm == null) {
            Log.w(TAG, "No TelephonyManager; cellular monitor inert")
            CellularState.setStatus(CellularState.Status.NO_TELEPHONY)
        }
        return tm
    }

    fun stop() {
        val cb = callback ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            context.getSystemService(TelephonyManager::class.java)?.unregisterTelephonyCallback(cb)
        }
        callback = null
        CellularState.clear()
        Log.i(TAG, "Cellular monitor stopped")
    }

    /**
     * Reads the current cell state once at startup instead of waiting for the
     * first change.
     *
     * onCellInfoChanged fires on CHANGE, so on a stationary device the first
     * callback can be a long time coming — the view sits on "waiting for a
     * radio update" and is indistinguishable from a monitor that is not
     * working. Some devices happen to deliver an immediate callback when the
     * listener registers; relying on that made startup device-dependent.
     *
     * Failure is non-fatal: the callback path is still live, so a refused or
     * empty read only means the first update arrives later.
     */
    @SuppressLint("MissingPermission")
    private fun primeFromCurrentState(tm: TelephonyManager) {
        runCatching { tm.allCellInfo.orEmpty() }
            .onSuccess { cells ->
                if (cells.isEmpty()) {
                    Log.i(TAG, "initial read returned no cells; waiting for a callback")
                    CellularState.setStatus(CellularState.Status.AWAITING_FIRST_UPDATE)
                } else {
                    handle(cells)
                }
            }
            .onFailure {
                Log.w(TAG, "initial cell read refused: ${it.message}")
                CellularState.setStatus(CellularState.Status.READ_REFUSED)
            }
    }

    internal fun handle(cellInfo: List<CellInfo>) {
        val serving = cellInfo.firstOrNull { it.isRegistered }
        if (serving == null) {
            // Distinguishing an empty delivery from "no registered cell" matters:
            // a background caller is handed an empty list rather than an error,
            // so silence here is ambiguous unless it is logged explicitly.
            Log.i(TAG, "onCellInfoChanged: ${cellInfo.size} records, none registered")
            return
        }
        val snapshot = toSnapshot(serving, cellInfo, System.currentTimeMillis())
        // PRIVACY: never log the cell identity tuple. (mcc, mnc, tac, ci) is a
        // globally unique tower identifier and is directly geolocatable — that
        // is exactly what OpenCelliD does, and what this feature's own
        // data-broker rules (androdr-079..083) exist to catch other apps doing.
        // Logging it every delivery would write a timestamped location trail
        // into logcat, which is readable via adb and captured in bugreports —
        // on a device whose whole threat model is that it may be targeted.
        //
        // The full snapshot IS retained, in the app-private findings store,
        // which is the access-controlled place for it. Logs carry SHAPE ONLY:
        // enough to tell "the field arrived populated" from "the field was
        // blanked", which is the diagnostic that matters.
        Log.i(
            TAG,
            "snapshot rat=${snapshot.rat} tac=${present(snapshot.tac)} " +
                "ci=${present(snapshot.ci)} pci=${present(snapshot.pci)} " +
                "earfcn=${present(snapshot.earfcn)} bw=${present(snapshot.bandwidthKhz)} " +
                "plmn=${present(snapshot.mcc)} op=${present(snapshot.operatorAlphaLong)} " +
                "neighbours=${snapshot.neighborCount} rsrp=${present(snapshot.servingRsrp)} " +
                "tacChanged=${snapshot.tacChanged} churn5m=${snapshot.tacChangesLast5m} " +
                "ratChanged=${snapshot.ratChanged}"
        )
        runCatching { engine.evaluateCellular(listOf(snapshot)) }
            .onSuccess { findings ->
                val triggered = findings.filter { it.triggered }
                triggered.forEach { Log.w(TAG, "Cellular finding: ${it.ruleId}") }
                CellularState.record(snapshot, triggered)
                persist(triggered, snapshot)
            }
            .onFailure {
                Log.e(TAG, "evaluateCellular failed: ${it.message}")
                // Still surface the snapshot: the radio view stays live even if
                // rule evaluation fails, so a broken rule cannot silently make
                // the monitor look dead.
                CellularState.record(snapshot, emptyList())
            }
    }

    /**
     * Records that monitoring began.
     *
     * Without this, an empty cellular timeline is ambiguous: it reads the same
     * whether the radio was clean or the monitor never ran. That distinction
     * is not academic here — cell info comes back EMPTY rather than erroring
     * when the caller is not permitted to read it, so a silent failure and a
     * quiet radio look identical. One row per session establishes the coverage
     * window an analyst needs to interpret the absence of findings.
     *
     * One row per monitor start is negligible next to the app_scanner rows
     * that already dominate the timeline.
     */
    private fun recordSessionStart() {
        val event = ForensicTimelineEvent(
            startTimestamp = System.currentTimeMillis(),
            kind = "event",
            source = TIMELINE_SOURCE,
            category = "cellular_session",
            description = "Cellular monitoring started",
            details = "monitor=active",
        )
        scope.launch {
            runCatching { repository.logCellularTimelineEvents(listOf(event)) }
                .onFailure { Log.e(TAG, "failed to record session start: ${it.message}") }
        }
    }

    /**
     * Writes triggered findings to the forensic timeline so they survive the
     * process. The live [CellularState] view is deliberately in-memory; this
     * is the durable record the field methodology adjudicates against, and it
     * is what puts cellular findings into the timeline UI and its exports.
     *
     * The full radio context goes in `details` because a finding without its
     * snapshot cannot be judged true or false after the fact.
     */
    private fun persist(triggered: List<Finding>, snapshot: CellularSnapshot) {
        if (triggered.isEmpty()) return
        val events = triggered.map { f ->
            ForensicTimelineEvent(
                startTimestamp = snapshot.capturedAt,
                kind = "event",
                source = TIMELINE_SOURCE,
                category = "network_anomaly",
                description = f.title,
                details = buildString {
                    append("rat=").append(snapshot.rat)
                    append(" tac=").append(snapshot.tac ?: "-")
                    append(" ci=").append(snapshot.ci ?: "-")
                    append(" pci=").append(snapshot.pci ?: "-")
                    append(" earfcn=").append(snapshot.earfcn ?: "-")
                    append(" plmn=").append(snapshot.mcc ?: "-").append('/')
                    append(snapshot.mnc ?: "-")
                    append(" op=").append(snapshot.operatorAlphaLong ?: "-")
                    append(" neighbours=").append(snapshot.neighborCount)
                    append(" rsrp=").append(snapshot.servingRsrp ?: "-")
                    append(" prevTac=").append(snapshot.previousTac ?: "-")
                    append(" churn5m=").append(snapshot.tacChangesLast5m)
                },
                ruleId = f.ruleId,
                attackTechniqueId = f.tags.firstOrNull { it.startsWith("attack.") }.orEmpty(),
                telemetrySource = snapshot.source,
            )
        }
        scope.launch {
            runCatching { repository.logCellularTimelineEvents(events) }
                .onFailure { Log.e(TAG, "failed to persist cellular findings: ${it.message}") }
        }
    }

    /** Android reports unavailable integers as Integer.MAX_VALUE. */
    private fun sentinel(value: Int): Int? = if (value == Int.MAX_VALUE) null else value

    /**
     * Log-safe field summary: reports whether a value arrived, never the value.
     * Used so logs can answer "is the platform blanking this field?" without
     * emitting anything that identifies a cell, and therefore a location.
     */
    private fun present(value: Any?): String = if (value == null) "null" else "set"

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

    companion object {
        internal const val TAG = "CellularMonitor"

        /**
         * Permissions the monitor genuinely needs. READ_PHONE_STATE is easy to
         * forget because it is not "a location permission", but without it
         * getAllCellInfo is refused just as surely.
         */
        val REQUIRED_PERMISSIONS = arrayOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.READ_PHONE_STATE,
        )

        /**
         * What to ASK for, which is a superset: Android 12+ refuses FINE unless
         * COARSE is requested alongside it.
         *
         * Required and requested live together deliberately. They were two
         * separate lists that drifted — the UI asked only for location while
         * the monitor also demanded READ_PHONE_STATE, so granting location
         * hid the request button while the monitor stayed blocked, and the
         * screen reported a permission problem with no way to fix it.
         */
        val REQUESTED_PERMISSIONS = arrayOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.READ_PHONE_STATE,
        )

        /** Single source of truth for "can the monitor run". */
        fun hasRequiredPermissions(context: Context): Boolean =
            REQUIRED_PERMISSIONS.all {
                ContextCompat.checkSelfPermission(context, it) ==
                    PackageManager.PERMISSION_GRANTED
            }
        const val TIMELINE_SOURCE = "cellular_monitor"
    }
}
