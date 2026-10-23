package com.androdr.sigma

import com.androdr.data.model.BatteryDailyEvent
import com.androdr.data.model.DatabasePathObservation
import com.androdr.data.model.PackageInstallHistoryEntry
import com.androdr.data.model.PlatformCompatChange
import com.androdr.data.model.TombstoneEvent
import com.androdr.data.model.WakelockAcquisition

/** Projects bug-report telemetry to [StoreRecord]s through each type's `toFieldMap()`. */
object BugReportRecordBuilders {
    const val TOMBSTONE_PARSER = "tombstone_parser"
    const val WAKELOCK_PARSER = "wakelock_parser"
    const val BATTERY_DAILY = "battery_daily"
    const val PACKAGE_INSTALL_HISTORY = "package_install_history"
    const val PLATFORM_COMPAT = "platform_compat"
    const val DB_INFO = "db_info"

    fun tombstones(t: List<TombstoneEvent>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun wakelocks(t: List<WakelockAcquisition>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun batteryDaily(t: List<BatteryDailyEvent>): List<StoreRecord> = t.map { StoreRecord(it.toFieldMap()) }
    fun packageInstallHistory(t: List<PackageInstallHistoryEntry>): List<StoreRecord> =
        t.map { StoreRecord(it.toFieldMap()) }
    fun platformCompat(t: List<PlatformCompatChange>): List<StoreRecord> =
        t.map { StoreRecord(it.toFieldMap()) }
    fun databasePathObservations(t: List<DatabasePathObservation>): List<StoreRecord> =
        t.map { StoreRecord(it.toFieldMap()) }

    /** Modules that already emit field maps (the generic bug-report path). */
    fun generic(records: List<Map<String, Any?>>): List<StoreRecord> = records.map { StoreRecord(it) }
}
