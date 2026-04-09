package com.androdr.data.model

/**
 * A single package install or uninstall event with a timestamp.
 *
 * Currently derivable only from bugreport `batterystats --history` output
 * (plan 5's `BatteryDailyParser`). Android's live `PackageManager` API
 * only exposes `firstInstallTime` and `lastUpdateTime` for currently-installed
 * packages, not a full history — this telemetry type fills that gap from
 * bugreport data.
 *
 * Source-agnostic: if a future Android API ever exposes install history,
 * the live scanner can emit the same type without changing rule code.
 *
 * @property packageName fully-qualified package name
 * @property eventType INSTALL, UNINSTALL, or UPDATE
 * @property timestamp epoch milliseconds
 * @property versionCode app version code at the time of the event, if known
 * @property source where this row came from (always BUGREPORT_IMPORT today;
 *                  no runtime producer currently exists)
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class PackageInstallHistoryEntry(
    val packageName: String,
    val eventType: PackageHistoryEventType,
    val timestamp: Long,
    val versionCode: Long?,
    val source: TelemetrySource,
    val capturedAt: Long,
)

enum class PackageHistoryEventType {
    INSTALL,
    UNINSTALL,
    UPDATE,
}
