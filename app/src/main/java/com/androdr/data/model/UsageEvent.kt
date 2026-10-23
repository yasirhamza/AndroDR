package com.androdr.data.model

/**
 * One app foreground/background transition read from UsageStatsManager.
 *
 * The `usage_stats` service is emitter-only: these records are stored and
 * shown on the timeline, but no rule may target them.
 *
 * @property timestamp when the transition happened (epoch ms)
 * @property appName user-visible label, or the package name when none resolves
 * @property eventType the timeline category (`app_foreground` / `app_background`)
 * @property capturedAt when the scan read this event (epoch ms)
 */
data class UsageEvent(
    val timestamp: Long,
    val packageName: String,
    val appName: String,
    val eventType: String,
    val source: TelemetrySource,
    val capturedAt: Long,
) {
    fun toFieldMap(): Map<String, Any?> = mapOf(
        "timestamp" to timestamp,
        "package_name" to packageName,
        "app_name" to appName,
        "event_type" to eventType,
        "source" to source.name,
        "captured_at" to capturedAt,
    )
}
