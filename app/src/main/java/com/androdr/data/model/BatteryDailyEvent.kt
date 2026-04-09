package com.androdr.data.model

/**
 * A single entry from Android's `batterystats --daily` output representing
 * a notable event in the per-day battery history. Currently captured from
 * imported bugreports only.
 *
 * Used by plan 6's new rules to detect anti-forensics patterns (e.g.,
 * package uninstall with known-bad IOC hit, version downgrade).
 *
 * @property dayIndex the day number within the bugreport's battery history
 * @property eventType e.g. "package_uninstall", "version_downgrade"
 * @property packageName affected package, if applicable
 * @property description free-form description from the bugreport entry
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class BatteryDailyEvent(
    val dayIndex: Int,
    val eventType: String,
    val packageName: String?,
    val description: String,
    val source: TelemetrySource,
    val capturedAt: Long,
)
