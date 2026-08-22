package com.androdr.cellular

import com.androdr.data.model.CellularSnapshot
import com.androdr.sigma.Finding
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Live Tier 1 radio state, for the on-device research view.
 *
 * Process-scoped and deliberately in-memory only, mirroring the
 * `DnsVpnService.isRunning` pattern already used by the Network screen. It is
 * a viewport onto the current radio, not a store: durable retention of
 * findings is a separate concern.
 *
 * PRIVACY NOTE — this intentionally holds the values that must never be
 * logged (see the spec's "never log the cell identity tuple"). The
 * distinction is exposure surface, not sensitivity: logcat is readable over
 * adb and captured in bugreports, whereas this never leaves the process and
 * is rendered only to the person holding the device, who is looking at their
 * own radio. Showing the operator their own TAC on screen is the point of the
 * feature; writing it to a shared log is the thing that was wrong.
 */
object CellularState {

    private val _latest = MutableStateFlow<CellularSnapshot?>(null)
    val latest: StateFlow<CellularSnapshot?> = _latest.asStateFlow()

    private val _triggered = MutableStateFlow<List<Finding>>(emptyList())
    val triggered: StateFlow<List<Finding>> = _triggered.asStateFlow()

    private val _deliveries = MutableStateFlow(0)

    /** Count of callback deliveries this session — shows the monitor is alive. */
    val deliveries: StateFlow<Int> = _deliveries.asStateFlow()

    fun record(snapshot: CellularSnapshot, findings: List<Finding>) {
        _latest.value = snapshot
        _deliveries.value = _deliveries.value + 1
        if (findings.isNotEmpty()) {
            // Keep newest first, bounded: this is a live view, not an archive.
            _triggered.value = (findings + _triggered.value).take(MAX_FINDINGS)
        }
    }

    fun clear() {
        _latest.value = null
        _triggered.value = emptyList()
        _deliveries.value = 0
    }

    private const val MAX_FINDINGS = 20
}
