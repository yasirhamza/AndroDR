package com.androdr.data.model

import kotlinx.serialization.Serializable

@Serializable
enum class KnownAppCategory {
    AOSP,
    GOOGLE,
    OEM,
    USER_APP
}

@Serializable
data class KnownAppEntry(
    val packageName: String,
    val displayName: String,
    val category: KnownAppCategory,
    val sourceId: String,
    val fetchedAt: Long
)
