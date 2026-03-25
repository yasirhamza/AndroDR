package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "domain_ioc_entries")
data class DomainIocEntry(
    @PrimaryKey val domain: String,
    val campaignName: String,
    val severity: String,
    val source: String,
    val fetchedAt: Long
)
