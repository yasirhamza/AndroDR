package com.androdr.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey
import kotlinx.serialization.Serializable

@Entity
@Serializable
data class DnsEvent(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val timestamp: Long,
    val domain: String,
    val appUid: Int,
    val appName: String?,
    val isBlocked: Boolean,
    val reason: String?
)
