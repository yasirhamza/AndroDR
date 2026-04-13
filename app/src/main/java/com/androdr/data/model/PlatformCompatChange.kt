package com.androdr.data.model

/**
 * A platform-compat framework ChangeId toggle record. Plan 6's
 * anti-analysis detection rule looks for specific ChangeId values
 * (e.g. DOWNSCALED = 168419799) that indicate targeted compatibility
 * overrides applied by an attacker or a debugging session.
 *
 * Parsed from bugreport `dumpsys platform_compat` output.
 *
 * @property changeId the compat ChangeId as a string (large numeric values)
 * @property packageName the affected package
 * @property enabled whether the ChangeId is currently enabled
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class PlatformCompatChange(
    val changeId: String,
    val packageName: String,
    val enabled: Boolean,
    val source: TelemetrySource,
    val capturedAt: Long,
)
