package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure
import com.androdr.util.reportSafe
import javax.inject.Inject
import javax.inject.Singleton

/** A signal row and its members, which are stored only in `signal_member` (spec §5.4). */
data class CorrelationSignal(val row: ForensicTimelineEvent, val members: List<AtomRef>)

/**
 * What one correlation pass produced: the signals found (including those found in a (rule, group)
 * before its cut-off) and one [NotEvaluatedReason.CORRELATION_INCOMPLETE] entry per rule the budget
 * cut off or never started.
 */
data class CorrelationResult(val signals: List<CorrelationSignal>, val incomplete: List<ScannerFailure>) {
    companion object {
        val NONE = CorrelationResult(emptyList(), emptyList())
    }
}

/**
 * Evaluates upstream-SIGMA-compliant correlation rules over correlation atoms (spec §5.2, §6):
 * timeline rows and exact-precision facts, keyed by [AtomRef].
 *
 * Inputs:
 *  - rules: parsed correlation rules to evaluate
 *  - atoms: candidate atoms (this scan's, plus a live scan's lookback)
 *  - bindings: atom ref -> atom rule IDs it satisfies ([SigmaRuleEngine.computeAtomBindings])
 *  - budget: the per-(rule, group) and total deadlines; checked, never thrown
 *
 * Each signal row carries `correlation_type`, `rule_id` and `member_count` in `details`; its
 * members go to `signal_member` only, so no row grows with chain size.
 */
@Singleton
@Suppress("TooManyFunctions") // one evaluator per correlation type plus the budget bookkeeping
class SigmaCorrelationEngine @Inject constructor() {

    /**
     * The [Finding]s to record on the scan for [signals] produced by [evaluate] (#350).
     * Each signal maps to its rule by id; severity is capped by the chain's effective
     * category exactly as [evaluate] caps the signal's own severity.
     */
    fun findingsFor(
        signals: List<CorrelationSignal>,
        rules: List<CorrelationRule>,
        atomRulesById: Map<String, SigmaRule> = emptyMap(),
    ): List<Finding> {
        val byId = rules.associateBy { it.id }
        return signals.mapNotNull { signal ->
            val rule = byId[signal.row.ruleId] ?: return@mapNotNull null
            CorrelationFindings.fromSignal(
                signal.row, rule, computeEffectiveCategory(rule.referencedRuleIds, atomRulesById)
            )
        }
    }

    /**
     * Runs [rules] over [atoms]. Per rule, atoms are first filtered to those bound to one of the
     * rule's steps, then grouped; groups run smallest first, so the largest (the adversarial ones)
     * run last. Every unfinished or unstarted (rule, group) is reported, never silently dropped.
     */
    fun evaluate(
        rules: List<CorrelationRule>,
        atoms: List<TimelineAtom>,
        bindings: Map<AtomRef, Set<String>>,
        atomRulesById: Map<String, SigmaRule> = emptyMap(),
        budget: CorrelationBudget = CorrelationBudget.unbounded(),
    ): CorrelationResult {
        if (rules.isEmpty()) return CorrelationResult.NONE
        // Binding (done by the caller under the same budget) or grouping overran the total
        // deadline: no rule ran, and no package is known yet.
        val grouped = groupAll(rules, atoms, bindings, budget) ?: return CorrelationResult(
            emptyList(), rules.map { notStarted(it) }
        )
        val signals = mutableListOf<CorrelationSignal>()
        val unfinished = LinkedHashMap<String, MutableList<String>>()
        for ((rule, groups) in grouped) {
            val effectiveRule = rule.copy(
                severity = SeverityCapPolicy.applyCap(
                    computeEffectiveCategory(rule.referencedRuleIds, atomRulesById), rule.severity
                ),
            )
            for ((key, group) in groups) {
                if (budget.totalExpired()) {
                    unfinished.getOrPut(rule.id) { mutableListOf() } += key
                    continue
                }
                val deadline = budget.groupDeadline()
                val outcome = evaluateGroup(effectiveRule, group, bindings) { budget.expired(deadline) }
                signals += outcome.signals
                if (!outcome.finished) unfinished.getOrPut(rule.id) { mutableListOf() } += key
            }
        }
        val byId = rules.associateBy { it.id }
        return CorrelationResult(signals, unfinished.map { (id, keys) -> notFinished(byId.getValue(id), keys) })
    }

    /**
     * Per rule, its step-bound atoms grouped by the rule's group key, each group sorted by time,
     * groups ordered smallest first. Null when the total deadline passed before grouping finished.
     */
    private fun groupAll(
        rules: List<CorrelationRule>,
        atoms: List<TimelineAtom>,
        bindings: Map<AtomRef, Set<String>>,
        budget: CorrelationBudget,
    ): List<Pair<CorrelationRule, List<Pair<String, List<TimelineAtom>>>>>? {
        if (budget.totalExpired()) return null
        return rules.map { rule ->
            val steps = rule.referencedRuleIds.toSet()
            val groups = HashMap<String, MutableList<TimelineAtom>>()
            for ((i, atom) in atoms.withIndex()) {
                if (i % CHECK_EVERY == 0 && budget.totalExpired()) return null
                if (bindings[atom.ref].orEmpty().any { it in steps }) {
                    groups.getOrPut(groupKey(atom, rule.groupBy)) { mutableListOf() } += atom
                }
            }
            val byTime = compareBy<TimelineAtom> { it.timestamp }.thenBy { it.ref }
            val ordered = groups.entries
                .map { (key, list) -> key to list.sortedWith(byTime) }
                .sortedWith(compareBy<Pair<String, List<TimelineAtom>>> { it.second.size }.thenBy { it.first })
            rule to ordered
        }
    }

    private fun evaluateGroup(
        rule: CorrelationRule, sorted: List<TimelineAtom>, bindings: Map<AtomRef, Set<String>>, cut: () -> Boolean,
    ): GroupOutcome = when (rule.type) {
        CorrelationType.TEMPORAL_ORDERED -> evaluateTemporalOrdered(rule, sorted, bindings, cut)
        CorrelationType.EVENT_COUNT -> evaluateEventCount(rule, sorted, cut)
        CorrelationType.TEMPORAL -> evaluateTemporalUnordered(rule, sorted, bindings, cut)
    }

    private class GroupOutcome(val signals: List<CorrelationSignal>, val finished: Boolean)

    /**
     * Determines the effective rule category for a correlation rule by inspecting
     * its member (referenced) rule categories.
     *
     * Propagation rule (spec §6):
     * - If ANY referenced rule is [RuleCategory.INCIDENT] → result is INCIDENT.
     * - If ALL referenced rules are [RuleCategory.DEVICE_POSTURE] → result is DEVICE_POSTURE.
     * - If NO referenced rules are known (e.g. misconfiguration) → safe default: INCIDENT (uncapped).
     *
     * Unknown rule IDs are skipped — they don't contribute to the decision.
     *
     * This is called at evaluation time to determine the effective category
     * before the cap policy is applied to the resulting correlation finding.
     */
    fun computeEffectiveCategory(
        referencedRuleIds: List<String>,
        atomRulesById: Map<String, SigmaRule>,
    ): RuleCategory {
        val knownCategories = referencedRuleIds.mapNotNull { atomRulesById[it]?.category }
        if (knownCategories.isEmpty()) return RuleCategory.INCIDENT
        return if (knownCategories.any { it == RuleCategory.INCIDENT }) {
            RuleCategory.INCIDENT
        } else {
            RuleCategory.DEVICE_POSTURE
        }
    }

    @Suppress("LoopWithTooManyJumpStatements", "ReturnCount") // chain matching breaks; a cut returns early
    private fun evaluateTemporalOrdered(
        rule: CorrelationRule,
        sorted: List<TimelineAtom>,
        bindings: Map<AtomRef, Set<String>>,
        cut: () -> Boolean,
    ): GroupOutcome {
        val results = mutableListOf<CorrelationSignal>()
        val firstStepRule = rule.referencedRuleIds.first()
        for (i in sorted.indices) {
            if (cut()) return GroupOutcome(results, finished = false)
            val e = sorted[i]
            if (firstStepRule !in bindings[e.ref].orEmpty()) continue
            val chain = mutableListOf(e)
            var nextStepIdx = 1
            for (j in (i + 1) until sorted.size) {
                if (cut()) return GroupOutcome(results, finished = false)
                val candidate = sorted[j]
                if (candidate.timestamp - e.timestamp > rule.timespanMs) break
                val needRule = rule.referencedRuleIds[nextStepIdx]
                if (needRule in bindings[candidate.ref].orEmpty()) {
                    chain += candidate
                    nextStepIdx++
                    if (nextStepIdx >= rule.referencedRuleIds.size) break
                }
            }
            if (chain.size == rule.referencedRuleIds.size) results += signal(rule, chain)
        }
        return GroupOutcome(results, finished = true)
    }

    /** Group atoms are already filtered to the rule's steps, so every one of them counts. */
    private fun evaluateEventCount(
        rule: CorrelationRule, matching: List<TimelineAtom>, cut: () -> Boolean,
    ): GroupOutcome {
        val results = mutableListOf<CorrelationSignal>()
        var i = 0
        var end = 0
        while (i < matching.size) {
            if (cut()) return GroupOutcome(results, finished = false)
            val windowEnd = matching[i].timestamp + rule.timespanMs
            if (end < i) end = i
            while (end < matching.size && matching[end].timestamp <= windowEnd) end++
            if (end - i >= rule.minEvents) {
                results += signal(rule, matching.subList(i, end))
                i = end
            } else {
                i++
            }
        }
        return GroupOutcome(results, finished = true)
    }

    @Suppress("LoopWithTooManyJumpStatements", "ReturnCount") // unordered-all-fire breaks on a match
    private fun evaluateTemporalUnordered(
        rule: CorrelationRule,
        sorted: List<TimelineAtom>,
        bindings: Map<AtomRef, Set<String>>,
        cut: () -> Boolean,
    ): GroupOutcome {
        val needed = rule.referencedRuleIds.toSet()
        val results = mutableListOf<CorrelationSignal>()
        for (i in sorted.indices) {
            if (cut()) return GroupOutcome(results, finished = false)
            val anchor = sorted[i]
            val window = mutableListOf(anchor)
            val seenRules = bindings[anchor.ref].orEmpty().intersect(needed).toMutableSet()
            for (j in (i + 1) until sorted.size) {
                if (cut()) return GroupOutcome(results, finished = false)
                if (sorted[j].timestamp - anchor.timestamp > rule.timespanMs) break
                window += sorted[j]
                seenRules += bindings[sorted[j].ref].orEmpty().intersect(needed)
                if (seenRules.containsAll(needed)) {
                    results += signal(rule, window)
                    break
                }
            }
        }
        return GroupOutcome(results, finished = true)
    }

    private fun groupKey(atom: TimelineAtom, groupBy: List<String>): String =
        when (groupBy.firstOrNull()) {
            "package_name" -> atom.packageName
            else -> ""
        }

    private fun signal(rule: CorrelationRule, members: List<TimelineAtom>): CorrelationSignal {
        val first = members.first()
        val last = members.last()
        val refs = members.map { it.ref }
        val detailsJson = """{"correlation_type":"${rule.type.name.lowercase()}",""" +
            """"rule_id":"${rule.id}","$MEMBER_COUNT":${refs.size}}"""
        val row = ForensicTimelineEvent(
            startTimestamp = first.timestamp,
            endTimestamp = last.timestamp,
            kind = "signal",
            category = "correlation",
            source = SOURCE,
            description = rule.displayLabel,
            details = detailsJson,
            packageName = first.packageName,
            ruleId = rule.id,
            correlationId = SignalIdentity.correlationId(rule.id, refs),
        )
        return CorrelationSignal(row, refs)
    }

    /** A rule-level "not started" entry for every rule (the pass could not read or bind its atoms). */
    fun notStarted(rules: List<CorrelationRule>): List<ScannerFailure> = rules.map { notStarted(it) }

    private fun notStarted(rule: CorrelationRule) = ScannerFailure(
        scanner = SCANNER,
        exception = NotEvaluatedReason.CORRELATION_INCOMPLETE.sentinel,
        message = "${reportSafe(rule.title)} (${reportSafe(rule.id)}): not started -- the correlation time " +
            "budget ran out first",
        ruleId = rule.id,
    )

    private fun notFinished(rule: CorrelationRule, keys: List<String>): ScannerFailure {
        val names = keys.map { if (it.isEmpty()) DEVICE_WIDE else reportSafe(it) }
        val shown = names.take(MAX_INCOMPLETE_PACKAGES)
        val more = names.size - shown.size
        val list = shown.joinToString(", ") + if (more > 0) " and $more more" else ""
        return ScannerFailure(
            scanner = SCANNER,
            exception = NotEvaluatedReason.CORRELATION_INCOMPLETE.sentinel,
            message = "${reportSafe(rule.title)} (${reportSafe(rule.id)}): not finished in time for $list",
            ruleId = rule.id,
            packages = shown,
            morePackages = more,
        )
    }

    companion object {
        const val SOURCE = "sigma_correlation_engine"
        const val MEMBER_COUNT = "member_count"
        const val SCANNER = "correlation"

        /** Packages one CORRELATION_INCOMPLETE entry names before "and K more" (spec §5.2). */
        const val MAX_INCOMPLETE_PACKAGES = 20

        /** The group label of a rule without `group-by`. */
        const val DEVICE_WIDE = "device-wide"

        /** Atoms grouped between two total-deadline checks. */
        private const val CHECK_EVERY = 256
    }
}
