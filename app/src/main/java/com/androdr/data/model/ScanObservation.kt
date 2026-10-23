package com.androdr.data.model

import androidx.room.Entity
import androidx.room.Index

/**
 * One scan's observation of a fact (spec §5.1). PK `(scanId, service, ordinal)` is the keyset
 * for per-scan reads and deletes; unique `(scanId, recordId)` drops an exact duplicate record
 * within one scan. [eventTime] is copied from the fact for ordered scan-filtered reads.
 * [strippedKeys] is the codec's bitmask of envelope keys removed from the stored body.
 */
@Entity(
    tableName = "scan_record",
    primaryKeys = ["scanId", "service", "ordinal"],
    indices = [
        Index(value = ["scanId", "recordId"], unique = true),
        Index(value = ["recordId"]),
        Index(value = ["scanId", "eventTime"]),
    ]
)
data class ScanObservation(
    val scanId: Long,
    val service: String,
    val ordinal: Int,
    val recordId: Long,
    val eventTime: Long?,
    val source: TelemetrySource,
    val capturedAt: Long,
    val strippedKeys: Int,
)
