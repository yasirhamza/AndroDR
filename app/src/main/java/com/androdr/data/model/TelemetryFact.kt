package com.androdr.data.model

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * A telemetry fact (spec §5.1): one distinct record, identified per service by [factKey]
 * (h128). [sourceKey] is the h128 of the source-supplied key (e.g. `dns:<id>`) and equals
 * `forensic_timeline.sourceEventKey` of rows derived from the same event (J1). The computed
 * columns ([subjectKey], [eventTime], [timePrecision], [category], [packageName]) are pinned by
 * the taxonomy contract hash. [id] is AUTOINCREMENT so a deleted fact's id is never reused by a
 * pin. A plain class because it holds `ByteArray`s.
 */
@Entity(
    tableName = "telemetry_record",
    indices = [
        Index(value = ["service", "factKey"], unique = true),
        Index(value = ["service", "subjectKey"]),
        Index(value = ["packageName", "eventTime"]),
        Index(value = ["eventTime"]),
        Index(value = ["sourceKey"]),
        Index(value = ["bodyHash"]),
    ]
)
@Suppress("LongParameterList") // a Room entity: one constructor parameter per table column
class TelemetryFact(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val service: String,
    val factKey: ByteArray,
    val sourceKey: ByteArray?,
    val subjectKey: String?,
    val eventTime: Long?,
    val timePrecision: String,
    val category: String?,
    val packageName: String?,
    val bodyHash: ByteArray,
    /**
     * The creating observation's envelope (spec §5.1): written once at insert and never updated
     * (`INSERT OR IGNORE` keeps the first), so a pinned fact whose observations are gone still
     * decodes with its true provenance and its stripped envelope keys restored.
     */
    val firstSource: TelemetrySource,
    val firstCapturedAt: Long,
    val firstStrippedKeys: Int,
)
