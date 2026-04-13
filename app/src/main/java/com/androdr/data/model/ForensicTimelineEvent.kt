package com.androdr.data.model

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
        Index("telemetrySource")
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
    val createdAt: Long = System.currentTimeMillis()
)
