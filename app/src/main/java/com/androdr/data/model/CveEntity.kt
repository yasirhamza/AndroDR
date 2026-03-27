package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "cve_entries")
data class CveEntity(
    @PrimaryKey val cveId: String,
    val description: String,
    val severity: String,
    val fixedInPatchLevel: String,
    val cisaDateAdded: String,
    val isActivelyExploited: Boolean,
    val vendorProject: String,
    val product: String,
    val lastUpdated: Long
)
