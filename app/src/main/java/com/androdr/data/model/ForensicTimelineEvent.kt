package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "forensic_timeline")
data class ForensicTimelineEvent(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val timestamp: Long,
    val timestampPrecision: String = "exact",
    val source: String,
    val category: String,
    val description: String,
    val details: String = "",
    val severity: String,
    val packageName: String = "",
    val appName: String = "",
    val processUid: Int = -1,
    val iocIndicator: String = "",
    val iocType: String = "",
    val iocSource: String = "",
    val campaignName: String = "",
    val correlationId: String = "",
    val ruleId: String = "",
    val scanResultId: Long = -1,
    val attackTechniqueId: String = "",
    val isFromBugreport: Boolean = false,
    val isFromRuntime: Boolean = false,
    val createdAt: Long = System.currentTimeMillis()
)
