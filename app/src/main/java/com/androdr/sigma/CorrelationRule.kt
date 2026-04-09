package com.androdr.sigma

enum class CorrelationType { TEMPORAL_ORDERED, EVENT_COUNT, TEMPORAL }

data class CorrelationRule(
    val id: String,
    val title: String,
    val type: CorrelationType,
    val referencedRuleIds: List<String>,
    val timespanMs: Long,
    val groupBy: List<String>,
    val minEvents: Int,            // for event_count, else 1
    val severity: String,
    val displayLabel: String,
    val displayCategory: String = "correlation",
)
