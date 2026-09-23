package com.androdr.sigma

import com.androdr.data.model.FileArtifactTelemetry
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure
import com.androdr.util.reportSafe

/**
 * Which rules had nothing to judge, and why.
 *
 * A rule evaluated against no evidence produces no finding, and a report built
 * from findings alone then reads exactly like a clean result. Two rules lived in
 * that gap: the CRITICAL artifact rule, whose paths an unprivileged app may not
 * read (#366), and the chain rules whose legs need event kinds only an imported
 * bug report carries (#370). Both are declared here as [ScannerFailure] entries
 * carrying a [NotEvaluatedReason], which the report renders as its own section
 * and which never count towards the partial-scan banner.
 *
 * Pure: (rules, evidence) -> declarations. No platform, no I/O.
 */
object RuleCoverage {

    /** Logsource service of the rules that inspect filesystem artifacts. */
    const val FILE_SERVICE = "file_scanner"

    /**
     * Stands in for a leg whose atom rule is not loaded, or binds to nothing. The
     * report turns it into words; keeping it a constant means no caller invents one.
     */
    const val UNBOUND_LEG = "(no rule loaded for this leg)"

    private const val FILE_SCANNER = "fileArtifactScanner"
    private const val CORRELATION = "correlation"

    /**
     * File rules cannot see a path the app was refused. Declared whenever any path
     * went unread, because an unread path was never checked -- "clear" for the rest
     * of the list is not a verdict on it.
     */
    fun unreadableArtifactSkips(
        rules: List<SigmaRule>,
        telemetry: List<FileArtifactTelemetry>,
    ): List<ScannerFailure> {
        if (telemetry.isEmpty()) return emptyList()
        val unreadable = telemetry.count { !it.accessible }
        if (unreadable == 0) return emptyList()
        return rules.filter { it.service == FILE_SERVICE }.map { rule ->
            ScannerFailure(
                scanner = FILE_SCANNER,
                exception = NotEvaluatedReason.UNREADABLE_PATHS.sentinel,
                // Feed-controlled text on a report line: same sanitiser the sibling
                // capability skip applies, for the same reason (a CR/LF in a title
                // forges report content).
                message = "${reportSafe(rule.title)} (${reportSafe(rule.id)}): $unreadable of " +
                    "${telemetry.size} path(s) could not be read on this device",
                ruleId = rule.id,
            )
        }
    }

    /**
     * A chain rule fires only if every leg has events to bind to. A leg whose atom
     * rule never loaded, or whose event kind nothing recorded, makes the whole chain
     * unevaluable -- silently, until now.
     */
    fun noEventSkips(
        rules: List<CorrelationRule>,
        atomCategoryByRuleId: Map<String, String>,
        presentCategories: Set<String>,
    ): List<ScannerFailure> = rules.mapNotNull { rule ->
        val legs = rule.referencedRuleIds.map { atomCategoryByRuleId[it] }.distinct()
        val missing = legs.filter { it == null || it !in presentCategories }
        // How many legs a rule needs decides when it is unevaluable. An ordered or
        // unordered chain needs every leg; an event-count rule counts events bound to
        // ANY of its referenced rules (SigmaCorrelationEngine.evaluateEventCount), so
        // it is only unevaluable when nothing it references was recorded at all.
        val unevaluable = when (rule.type) {
            CorrelationType.EVENT_COUNT -> missing.size == legs.size
            CorrelationType.TEMPORAL_ORDERED, CorrelationType.TEMPORAL -> missing.isNotEmpty()
        }
        if (!unevaluable) {
            null
        } else {
            ScannerFailure(
                scanner = CORRELATION,
                exception = NotEvaluatedReason.NO_EVENTS_TO_CHECK.sentinel,
                // The sentence belongs to the reader, so it is composed at render time
                // from [missingEvidence]; the message carries only what names the rule.
                message = "${reportSafe(rule.title)} (${reportSafe(rule.id)})",
                ruleId = rule.id,
                missingEvidence = missing.map { it ?: UNBOUND_LEG },
            )
        }
    }

    /** As [noEventSkips], reading the recorded categories off the events themselves. */
    fun noEventSkipsFor(
        rules: List<CorrelationRule>,
        atomCategoryByRuleId: Map<String, String>,
        events: List<ForensicTimelineEvent>,
    ): List<ScannerFailure> =
        noEventSkips(rules, atomCategoryByRuleId, events.mapTo(HashSet()) { it.category })

}
