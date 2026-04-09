package com.androdr.data.model

/**
 * A snapshot of a system property extracted from a bugreport.
 *
 * Enables rules that evaluate `ro.*` and `persist.*` properties (bootloader
 * state, verified boot state, build fingerprint, etc.) to work on imported
 * bugreports the same way they work on live scans via `DeviceAuditor`.
 *
 * @property key the system property key (e.g. `ro.boot.verifiedbootstate`)
 * @property value the system property value at the time of the snapshot
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class SystemPropertySnapshot(
    val key: String,
    val value: String,
    val source: TelemetrySource,
    val capturedAt: Long,
)
