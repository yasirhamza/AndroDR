package com.androdr.data.model

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "forensic_timeline",
    indices = [
        Index("startTimestamp"),
        Index("packageName"),
        Index("source"),
        Index("kind"),
        // Serves telemetrySource lookups through its prefix and the 30-day prune as a range (spec §5.6).
        Index(value = ["telemetrySource", "createdAt"]),
        Index("recordId"),
        Index("sourceEventKey"),
        Index(value = ["scanResultId", "startTimestamp"]),
        Index(value = ["packageName", "startTimestamp"]),
    ]
)
data class ForensicTimelineEvent(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val startTimestamp: Long,
    val endTimestamp: Long? = null,
    val kind: String = "event",
    val timestampPrecision: String = "exact",
    val source: String,
    val category: String,
    val description: String,
    val details: String = "",
    val packageName: String = "",
    val appName: String = "",
    val processUid: Int = -1,
    val iocIndicator: String = "",
    val iocType: String = "",
    val iocSource: String = "",
    val campaignName: String = "",
    val apkHash: String = "",
    val correlationId: String = "",
    val ruleId: String = "",
    val scanResultId: Long = -1,
    val attackTechniqueId: String = "",
    val telemetrySource: TelemetrySource = TelemetrySource.LIVE_SCAN,
    val createdAt: Long = System.currentTimeMillis(),
    /** The `telemetry_record` fact behind this row, if any; pins that fact (spec §5.1 Pins). */
    val recordId: Long? = null,
    /** h128 of the source event key — the same hash as `telemetry_record.sourceKey` (J1). */
    val sourceEventKey: ByteArray? = null,
    /** The finding's level, for finding rows (backfilled for legacy rows by MIGRATION_19_20). */
    val level: String? = null,
    /** Audit/closure rows that survive scan deletion and "Clear all". */
    @ColumnInfo(defaultValue = "0")
    val persistent: Boolean = false,
) {
    // A data class (callers rely on copy()), so equality is written out to compare
    // [sourceEventKey] by content rather than by array identity.
    @Suppress("CyclomaticComplexMethod")
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ForensicTimelineEvent) return false
        return id == other.id && startTimestamp == other.startTimestamp && endTimestamp == other.endTimestamp &&
            kind == other.kind && timestampPrecision == other.timestampPrecision && source == other.source &&
            category == other.category && description == other.description && details == other.details &&
            packageName == other.packageName && appName == other.appName && processUid == other.processUid &&
            iocIndicator == other.iocIndicator && iocType == other.iocType && iocSource == other.iocSource &&
            campaignName == other.campaignName && apkHash == other.apkHash &&
            correlationId == other.correlationId && ruleId == other.ruleId &&
            scanResultId == other.scanResultId && attackTechniqueId == other.attackTechniqueId &&
            telemetrySource == other.telemetrySource && createdAt == other.createdAt &&
            recordId == other.recordId && sourceEventKey.contentEquals(other.sourceEventKey) &&
            level == other.level && persistent == other.persistent
    }

    override fun hashCode(): Int = listOf(
        id, startTimestamp, endTimestamp, kind, timestampPrecision, source, category, description, details,
        packageName, appName, processUid, iocIndicator, iocType, iocSource, campaignName, apkHash, correlationId,
        ruleId, scanResultId, attackTechniqueId, telemetrySource, createdAt, recordId,
        sourceEventKey?.contentHashCode(), level, persistent,
    ).hashCode()
}
