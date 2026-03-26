package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "cert_hash_ioc_entries")
data class CertHashIocEntry(
    @PrimaryKey val certHash: String,
    val familyName: String,
    val category: String,
    val severity: String,
    val description: String,
    val source: String,
    val fetchedAt: Long
)
