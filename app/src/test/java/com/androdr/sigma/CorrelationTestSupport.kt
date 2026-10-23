package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent

/**
 * Runs the correlator over timeline rows only (every row a [Row] atom, bindings keyed by row id)
 * with no time budget — the shape the pre-C2 engine tests were written in. Returns the signals.
 */
internal fun SigmaCorrelationEngine.evaluateRows(
    rules: List<CorrelationRule>,
    events: List<ForensicTimelineEvent>,
    bindings: Map<Long, Set<String>>,
    atomRulesById: Map<String, SigmaRule> = emptyMap(),
): List<CorrelationSignal> = evaluate(
    rules, events.map { it.asAtom() }, bindings.mapKeys { Row(it.key) }, atomRulesById,
).also { check(it.incomplete.isEmpty()) { "unbounded run reported incomplete: ${it.incomplete}" } }.signals

/** The `member_count` a signal row's details carry. */
internal val ForensicTimelineEvent.memberCount: Int?
    get() = Regex(""""member_count"\s*:\s*(\d+)""").find(details)?.groupValues?.get(1)?.toInt()

/** Row-only bindings keyed by row id (the pre-C2 shape), for assertions. */
internal fun SigmaRuleEngine.rowBindings(events: List<ForensicTimelineEvent>): Map<Long, Set<String>> =
    computeAtomBindings(events.map { it.asAtom() }).mapKeys { it.key.id }
