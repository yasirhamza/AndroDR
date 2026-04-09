package com.androdr.sigma

/**
 * Enforces the severity cap policy: findings from rules in certain categories
 * have their severity clamped at build time.
 *
 * Current policy (see spec §6):
 * - [RuleCategory.INCIDENT] — uncapped. Any declared severity passes through.
 * - [RuleCategory.DEVICE_POSTURE] — clamped at `medium`. Rules declaring `high`
 *   or `critical` produce findings with `level = medium` instead. Rules declaring
 *   `medium`, `low`, or `informational` are unaffected.
 *
 * Rationale: posture issues represent potential compromise (a condition), not
 * actual compromise (an incident). They must not out-shout real findings in
 * the UI or report summary. See [RuleCategory] docs and the spec at
 * `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §6 for the full argument.
 *
 * Correlation rules that combine posture with an incident leg are promoted
 * via the propagation rule in [SigmaCorrelationEngine], not via this policy.
 */
object SeverityCapPolicy {

    /**
     * Per-category maximum permitted finding severity. Rules whose category
     * is absent from this map are uncapped.
     *
     * Severity ordering (highest to lowest): critical > high > medium > low > informational.
     */
    private val caps: Map<RuleCategory, String> = mapOf(
        RuleCategory.DEVICE_POSTURE to "medium",
    )

    /**
     * Ordered list of severity values used for clamping comparisons.
     * Index 0 is the highest severity. A declared level is clamped to the cap
     * iff its index is lower (i.e. higher severity) than the cap's index.
     */
    private val severityOrder: List<String> = listOf(
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    )

    /**
     * Applies the cap for [category] to [declared] severity. Returns the
     * effective severity after clamping.
     *
     * - If [category] has no cap, returns [declared] unchanged (lowercased).
     * - If [declared] severity is already at or below the cap, returns it unchanged.
     * - If [declared] exceeds the cap, returns the cap value.
     *
     * Input [declared] is case-insensitive; output is always lowercase.
     */
    fun applyCap(category: RuleCategory, declared: String): String {
        val normalizedDeclared = declared.lowercase()
        val cap = caps[category] ?: return normalizedDeclared

        val declaredIdx = severityOrder.indexOf(normalizedDeclared)
        val capIdx = severityOrder.indexOf(cap)

        // Unknown severity values pass through unchanged — the parser should
        // have rejected them earlier.
        if (declaredIdx == -1 || capIdx == -1) return normalizedDeclared

        // Lower index = higher severity. Clamp if declared is higher than cap.
        return if (declaredIdx < capIdx) cap else normalizedDeclared
    }
}
