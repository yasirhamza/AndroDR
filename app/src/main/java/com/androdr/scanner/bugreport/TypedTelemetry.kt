package com.androdr.scanner.bugreport

import com.androdr.data.model.BatteryDailyEvent
import com.androdr.data.model.DatabasePathObservation
import com.androdr.data.model.PackageInstallHistoryEntry
import com.androdr.data.model.PlatformCompatChange
import com.androdr.data.model.SystemPropertySnapshot
import com.androdr.data.model.TombstoneEvent
import com.androdr.data.model.WakelockAcquisition

/**
 * The typed records one bug-report module (or the whole analysis) produced, one list per
 * record type. Every list holds every fact the parser saw; curation belongs in rules.
 */
data class TypedTelemetry(
    val tombstoneEvents: List<TombstoneEvent> = emptyList(),
    val wakelockAcquisitions: List<WakelockAcquisition> = emptyList(),
    val batteryDailyEvents: List<BatteryDailyEvent> = emptyList(),
    val packageInstallHistory: List<PackageInstallHistoryEntry> = emptyList(),
    val platformCompatChanges: List<PlatformCompatChange> = emptyList(),
    val databasePathObservations: List<DatabasePathObservation> = emptyList(),
    val systemPropertySnapshots: List<SystemPropertySnapshot> = emptyList(),
) {
    operator fun plus(other: TypedTelemetry): TypedTelemetry = TypedTelemetry(
        tombstoneEvents + other.tombstoneEvents,
        wakelockAcquisitions + other.wakelockAcquisitions,
        batteryDailyEvents + other.batteryDailyEvents,
        packageInstallHistory + other.packageInstallHistory,
        platformCompatChanges + other.platformCompatChanges,
        databasePathObservations + other.databasePathObservations,
        systemPropertySnapshots + other.systemPropertySnapshots,
    )
}
