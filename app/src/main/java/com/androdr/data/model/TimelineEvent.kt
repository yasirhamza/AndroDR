package com.androdr.data.model

data class TimelineEvent(
    val timestamp: Long,
    val source: String,
    val category: String,
    val description: String,
    val severity: String
)
