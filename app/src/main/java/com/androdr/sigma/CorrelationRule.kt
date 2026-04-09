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
    /**
     * Computed at evaluation time from member rule categories via propagation:
     * if ANY referenced rule is [RuleCategory.INCIDENT], this is INCIDENT;
     * otherwise DEVICE_POSTURE. See spec §6 "Correlation rule propagation".
     *
     * Used for severity cap enforcement: a correlation inheriting INCIDENT
     * is uncapped; one inheriting DEVICE_POSTURE is clamped to medium.
     *
     * Defaults to INCIDENT (the safe/uncapped default) so existing test
     * fixtures and parser code that don't yet populate this field continue
     * to work. Production usage populates it via SigmaCorrelationEngine.computeEffectiveCategory().
     */
    val effectiveCategory: RuleCategory = RuleCategory.INCIDENT,
)
