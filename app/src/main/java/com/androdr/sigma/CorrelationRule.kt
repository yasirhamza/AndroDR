package com.androdr.sigma

enum class CorrelationType { TEMPORAL_ORDERED, EVENT_COUNT, TEMPORAL }

/**
 * A parsed SIGMA correlation rule.
 *
 * Unlike [SigmaRule] (detection/atom rules), `CorrelationRule` does NOT
 * declare a [RuleCategory] field. The effective category of a correlation
 * is **derived at evaluation time** from its member rule categories via
 * [SigmaCorrelationEngine.computeEffectiveCategory]: if any member rule
 * is [RuleCategory.INCIDENT], the correlation is INCIDENT; otherwise
 * DEVICE_POSTURE. See spec §6 for the propagation rule.
 *
 * Category is never stored on this class because it would diverge from
 * member rule categories if they changed independently.
 */
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
