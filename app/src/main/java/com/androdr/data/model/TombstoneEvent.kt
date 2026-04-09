package com.androdr.data.model

/**
 * A parsed Android tombstone record representing a single process crash.
 * Plan 6's new `sigma_androdr_crash_loop_anti_forensics.yml` rule evaluates
 * these via correlation (multiple crashes for the same package within a
 * time window indicate potential exploit-then-crash behavior).
 *
 * Parsed from bugreport `tombstones/` section by plan 5's `TombstoneParser`.
 *
 * @property processName the crashed process name
 * @property packageName the owning package, if derivable
 * @property signalNumber the crash signal (e.g. 11 for SIGSEGV), null for abort
 * @property abortMessage the abort reason for non-signal aborts
 * @property crashTimestamp epoch milliseconds from the tombstone header
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class TombstoneEvent(
    val processName: String,
    val packageName: String?,
    val signalNumber: Int?,
    val abortMessage: String?,
    val crashTimestamp: Long,
    val source: TelemetrySource,
    val capturedAt: Long,
)
