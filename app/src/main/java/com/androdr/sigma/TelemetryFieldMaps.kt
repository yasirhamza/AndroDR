package com.androdr.sigma

import com.androdr.data.model.BatteryDailyEvent
import com.androdr.data.model.DatabasePathObservation
import com.androdr.data.model.PackageInstallHistoryEntry
import com.androdr.data.model.PlatformCompatChange
import com.androdr.data.model.TombstoneEvent
import com.androdr.data.model.WakelockAcquisition

/**
 * Plan-6 `.toFieldMap()` extensions for the new telemetry types added in
 * plan 2. Lives in the sigma package (not `com.androdr.data.model`) because
 * plan 6 is forbidden to touch files under `com/androdr/data/model/`.
 *
 * Field names are snake_case to match SIGMA rule convention. Callers
 * (SigmaRuleEngine.evaluateXxx()) convert each typed telemetry instance
 * to the `Map<String, Any?>` record shape SigmaRuleEvaluator expects.
 */

internal fun TombstoneEvent.toFieldMap(): Map<String, Any?> = mapOf(
    "process_name" to processName,
    "package_name" to packageName,
    "signal_number" to signalNumber,
    "abort_message" to abortMessage,
    "crash_timestamp" to crashTimestamp,
    "source" to source.name,
    "captured_at" to capturedAt,
)

internal fun WakelockAcquisition.toFieldMap(): Map<String, Any?> = mapOf(
    "package_name" to packageName,
    "wakelock_tag" to wakelockTag,
    "acquired_at" to acquiredAt,
    "duration_millis" to durationMillis,
    "source" to source.name,
    "captured_at" to capturedAt,
)

internal fun BatteryDailyEvent.toFieldMap(): Map<String, Any?> = mapOf(
    "day_index" to dayIndex,
    "event_type" to eventType,
    "package_name" to packageName,
    "description" to description,
    "source" to source.name,
    "captured_at" to capturedAt,
)

internal fun PackageInstallHistoryEntry.toFieldMap(): Map<String, Any?> = mapOf(
    "package_name" to packageName,
    "event_type" to eventType.name,
    "timestamp" to timestamp,
    "version_code" to versionCode,
    "source" to source.name,
    "captured_at" to capturedAt,
)

internal fun PlatformCompatChange.toFieldMap(): Map<String, Any?> = mapOf(
    "change_id" to changeId,
    "package_name" to packageName,
    "enabled" to enabled,
    "source" to source.name,
    "captured_at" to capturedAt,
)

internal fun DatabasePathObservation.toFieldMap(): Map<String, Any?> = mapOf(
    "file_path" to filePath,
    "process_name" to processName,
    "package_name" to packageName,
    "observation_timestamp" to observationTimestamp,
    "source" to source.name,
    "captured_at" to capturedAt,
)
