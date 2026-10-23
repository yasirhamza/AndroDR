package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent

/**
 * Turns a correlation signal into the [Finding] recorded on the scan that produced it.
 *
 * A signal -- a chain of events such as a sideloaded install followed by a
 * device-admin grant -- used to exist only as a timeline row: no severity, no effect
 * on overall risk, absent from the report's findings section (#350). It is the
 * strongest evidence the app produces, so it is a finding like any other, in the
 * [FindingCategory.CORRELATION] bucket. The signal row is still written, because the
 * Timeline shows a chain as that row (the cluster head that expands into its members).
 *
 * Severity follows the same policy as every other finding: the rule's declared
 * severity, capped when every leg of the chain is a device-posture condition.
 *
 * The finding carries the chain's `member_count`; the members themselves live only in
 * `signal_member` (spec §5.4), so no finding grows with chain size.
 */
object CorrelationFindings {

    private val MEMBER_COUNT = Regex(""""member_count"\s*:\s*(\d+)""")

    fun fromSignal(
        signal: ForensicTimelineEvent,
        rule: CorrelationRule,
        effectiveCategory: RuleCategory,
    ): Finding {
        val memberCount = MEMBER_COUNT.find(signal.details)?.groupValues?.get(1)
        val context = buildMap {
            put("package_name", signal.packageName)
            put("correlation_id", signal.correlationId)
            memberCount?.let { put(SigmaCorrelationEngine.MEMBER_COUNT, it) }
            put("chain_start", signal.startTimestamp.toString())
            put("chain_end", (signal.endTimestamp ?: signal.startTimestamp).toString())
        }
        return Finding(
            ruleId = rule.id,
            title = rule.displayLabel,
            description = rule.description,
            level = SeverityCapPolicy.applyCap(effectiveCategory, rule.severity),
            category = FindingCategory.CORRELATION,
            tags = rule.tags,
            triggered = true,
            ruleCategory = effectiveCategory.name,
            matchContext = context,
        )
    }
}
