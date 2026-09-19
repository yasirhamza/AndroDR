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
 */
object CorrelationFindings {

    private val MEMBER_IDS = Regex(""""member_event_ids"\s*:\s*"([^"]*)"""")

    fun fromSignal(
        signal: ForensicTimelineEvent,
        rule: CorrelationRule,
        effectiveCategory: RuleCategory,
    ): Finding {
        val memberIds = MEMBER_IDS.find(signal.details)?.groupValues?.get(1).orEmpty()
        return Finding(
            ruleId = rule.id,
            title = rule.displayLabel,
            description = rule.description,
            level = SeverityCapPolicy.applyCap(effectiveCategory, rule.severity),
            category = FindingCategory.CORRELATION,
            tags = rule.tags,
            triggered = true,
            matchContext = mapOf(
                "package_name" to signal.packageName,
                "correlation_id" to signal.correlationId,
                "member_event_ids" to memberIds,
                "chain_start" to signal.startTimestamp.toString(),
                "chain_end" to (signal.endTimestamp ?: signal.startTimestamp).toString(),
            ),
        )
    }
}
