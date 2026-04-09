package com.androdr.data.model

/**
 * A structured wakelock acquisition record parsed from bugreport power
 * sections. Plan 6's new `sigma_androdr_persistent_wakelock.yml` rule
 * evaluates wakelock density over time windows to flag always-on surveillance
 * behavior — though the rule ships disabled-by-default pending UAT
 * threshold calibration (#87).
 *
 * @property packageName the package holding the wakelock
 * @property wakelockTag the tag string identifying the wakelock purpose
 * @property acquiredAt epoch milliseconds when the wakelock was acquired
 * @property durationMillis how long it was held, or null if still held / unknown
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class WakelockAcquisition(
    val packageName: String,
    val wakelockTag: String,
    val acquiredAt: Long,
    val durationMillis: Long?,
    val source: TelemetrySource,
    val capturedAt: Long,
)
