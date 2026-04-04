package com.androdr.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "known_app_entries")
data class KnownAppDbEntry(
    @PrimaryKey val packageName: String,
    val displayName: String,
    val category: String,   // KnownAppCategory.name
    val sourceId: String,
    val fetchedAt: Long,
    val certHash: String? = null
)
