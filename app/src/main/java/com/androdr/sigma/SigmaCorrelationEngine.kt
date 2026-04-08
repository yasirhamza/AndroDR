package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Evaluates upstream-SIGMA-compliant correlation rules over a list of timeline events.
 *
 * Inputs:
 *  - rules: parsed correlation rules to evaluate
 *  - events: candidate events (typically a per-rule windowed slice of forensic_timeline)
 *  - bindings: map of eventId -> set of atom rule IDs that the event satisfies.
 *    Computed by SigmaRuleEngine after detection runs.
 *
 * Output: list of ForensicTimelineEvent rows with kind = "signal" representing
 * each cluster that fired.
 *
 * Note on matchContext: the existing ForensicTimelineEvent has no `matchContext`
 * map column. The three correlation metadata keys (correlation_type, rule_id,
 * member_event_ids) are encoded as a small JSON object in the existing `details`
 * field. Timeline UI parses it back. A future schema bump can promote
 * matchContext to a real column if it grows.
 */
@Singleton
class SigmaCorrelationEngine @Inject constructor() {

    fun evaluate(
        rules: List<CorrelationRule>,
        events: List<ForensicTimelineEvent>,
        bindings: Map<Long, Set<String>>
    ): List<ForensicTimelineEvent> {
        val signals = mutableListOf<ForensicTimelineEvent>()
        rules.forEach { rule ->
            signals += when (rule.type) {
                CorrelationType.TEMPORAL_ORDERED -> evaluateTemporalOrdered(rule, events, bindings)
                CorrelationType.EVENT_COUNT      -> evaluateEventCount(rule, events, bindings)
                CorrelationType.TEMPORAL         -> evaluateTemporalUnordered(rule, events, bindings)
            }
        }
        return signals
    }

    @Suppress("LoopWithTooManyJumpStatements") // chain-matching loop legitimately uses break/continue
    private fun evaluateTemporalOrdered(
        rule: CorrelationRule,
        events: List<ForensicTimelineEvent>,
        bindings: Map<Long, Set<String>>
    ): List<ForensicTimelineEvent> {
        val grouped = events.groupBy { groupKey(it, rule.groupBy) }
        val results = mutableListOf<ForensicTimelineEvent>()
        grouped.forEach { (_, groupEvents) ->
            val sorted = groupEvents.sortedBy { it.startTimestamp }
            val firstStepRule = rule.referencedRuleIds.first()
            sorted.forEachIndexed { i, e ->
                if (firstStepRule !in (bindings[e.id] ?: emptySet())) return@forEachIndexed
                val chain = mutableListOf(e)
                var nextStepIdx = 1
                for (j in (i + 1) until sorted.size) {
                    val candidate = sorted[j]
                    if (candidate.startTimestamp - e.startTimestamp > rule.timespanMs) break
                    val needRule = rule.referencedRuleIds[nextStepIdx]
                    if (needRule in (bindings[candidate.id] ?: emptySet())) {
                        chain += candidate
                        nextStepIdx++
                        if (nextStepIdx >= rule.referencedRuleIds.size) break
                    }
                }
                if (chain.size == rule.referencedRuleIds.size) {
                    results += signal(rule, chain)
                }
            }
        }
        return results
    }

    private fun evaluateEventCount(
        rule: CorrelationRule,
        events: List<ForensicTimelineEvent>,
        bindings: Map<Long, Set<String>>
    ): List<ForensicTimelineEvent> {
        val refRules = rule.referencedRuleIds.toSet()
        val grouped = events.groupBy { groupKey(it, rule.groupBy) }
        val results = mutableListOf<ForensicTimelineEvent>()
        grouped.forEach { (_, groupEvents) ->
            val matching = groupEvents
                .filter { (bindings[it.id] ?: emptySet()).any { id -> id in refRules } }
                .sortedBy { it.startTimestamp }
            var i = 0
            while (i < matching.size) {
                val windowEnd = matching[i].startTimestamp + rule.timespanMs
                val window = matching.subList(i, matching.size).takeWhile { it.startTimestamp <= windowEnd }
                if (window.size >= rule.minEvents) {
                    results += signal(rule, window)
                    i += window.size
                } else {
                    i++
                }
            }
        }
        return results
    }

    @Suppress("LoopWithTooManyJumpStatements") // unordered-all-fire uses break to short-circuit on match
    private fun evaluateTemporalUnordered(
        rule: CorrelationRule,
        events: List<ForensicTimelineEvent>,
        bindings: Map<Long, Set<String>>
    ): List<ForensicTimelineEvent> {
        val needed = rule.referencedRuleIds.toSet()
        val grouped = events.groupBy { groupKey(it, rule.groupBy) }
        val results = mutableListOf<ForensicTimelineEvent>()
        grouped.forEach { (_, groupEvents) ->
            val sorted = groupEvents.sortedBy { it.startTimestamp }
            for (i in sorted.indices) {
                val anchor = sorted[i]
                val window = mutableListOf(anchor)
                val seenRules = (bindings[anchor.id] ?: emptySet()).intersect(needed).toMutableSet()
                for (j in (i + 1) until sorted.size) {
                    if (sorted[j].startTimestamp - anchor.startTimestamp > rule.timespanMs) break
                    window += sorted[j]
                    seenRules += (bindings[sorted[j].id] ?: emptySet()).intersect(needed)
                    if (seenRules.containsAll(needed)) {
                        results += signal(rule, window)
                        break
                    }
                }
            }
        }
        return results
    }

    private fun groupKey(event: ForensicTimelineEvent, groupBy: List<String>): String =
        when (groupBy.firstOrNull()) {
            "package_name" -> event.packageName
            null -> ""
            else -> ""
        }

    private fun signal(rule: CorrelationRule, members: List<ForensicTimelineEvent>): ForensicTimelineEvent {
        val first = members.first()
        val last = members.last()
        val memberIds = members.joinToString(",") { it.id.toString() }
        val detailsJson = """{"correlation_type":"${rule.type.name.lowercase()}",""" +
            """"rule_id":"${rule.id}","member_event_ids":"$memberIds"}"""
        return ForensicTimelineEvent(
            scanResultId = first.scanResultId,
            startTimestamp = first.startTimestamp,
            endTimestamp = last.startTimestamp,
            kind = "signal",
            category = "correlation",
            source = "sigma_correlation_engine",
            description = rule.displayLabel,
            details = detailsJson,
            severity = rule.severity,
            packageName = first.packageName,
            ruleId = rule.id,
            correlationId = "${rule.id}:$memberIds"
        )
    }
}
