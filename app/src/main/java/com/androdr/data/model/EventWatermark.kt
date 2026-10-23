package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Per-service collection watermark for live event sources (spec §5.2): [position] is the last
 * collected `DnsEvent.id` or event time, advanced by the committed scan [scanId].
 */
@Entity(tableName = "event_watermark")
data class EventWatermark(
    @PrimaryKey val service: String,
    val position: Long,
    val scanId: Long,
)
