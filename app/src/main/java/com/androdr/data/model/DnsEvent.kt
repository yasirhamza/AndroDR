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
    /**
     * Whether the DNS response was replaced with NXDOMAIN (block mode).
     * Note: UI display uses [reason] != null for "matched" status, not this field.
     * This field records the actual blocking action taken.
     */
    val isBlocked: Boolean,
    val reason: String?
)
