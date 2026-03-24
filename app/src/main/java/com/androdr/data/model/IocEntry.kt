package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "ioc_entries")
data class IocEntry(
    @PrimaryKey
    val packageName: String,
    val name: String,
    val category: String,
    val severity: String,
    val description: String,
    /** Which feed produced this entry, e.g. "community_json" or "stalkerware_indicators". */
    val source: String,
    /** Epoch millis when this entry was last fetched. */
    val fetchedAt: Long
)
