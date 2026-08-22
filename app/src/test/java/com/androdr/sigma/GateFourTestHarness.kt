package com.androdr.sigma

/**
 * Gate 4 test harness: verifies that a [SigmaRule] fires on all supplied
 * true-positive records and stays silent on all true-negative records.
 *
 * Intended for use in unit tests that validate rule authoring quality.
 */
data class Gate4Result(
    val pass: Boolean,
    val tpFired: Boolean,
    val tnClean: Boolean,
    val errors: List<String>
)

object GateFourTestHarness {

    /**
     * Run gate-4 validation for a single rule.
     *
     * @param rule           The [SigmaRule] under test.
     * @param truePositives  Records that MUST produce a triggered finding.
     * @param trueNegatives  Records that MUST NOT produce a triggered finding
     *                       (a report_safe_state rule's safe-state finding,
     *                       triggered=false, is allowed here).
     * @param iocStubs       Optional IOC lookup stubs: lookup-name → set of
     *                       string values that should be considered "known bad".
     *                       Any key not referenced by the rule's detection
     *                       selections is reported as a warning in [Gate4Result.errors].
     */
    fun runGate4(
        rule: SigmaRule,
        truePositives: List<Map<String, Any?>>,
        trueNegatives: List<Map<String, Any?>>,
        iocStubs: Map<String, Set<String>> = emptyMap()
    ): Gate4Result {
        val errors = mutableListOf<String>()

        // Build iocLookups: each stub key maps to a lambda that checks set membership.
        val iocLookups: Map<String, (Any) -> Boolean> = iocStubs.mapValues { (_, stubSet) ->
            { value: Any -> value.toString() in stubSet }
        }

        // Warn if any iocStubs key is not referenced by any IOC_LOOKUP matcher in the rule.
        val referencedLookupNames: Set<String> = rule.detection.selections.values
            .flatMap { selection -> selection.fieldMatchers }
            .filter { matcher -> matcher.modifier == SigmaModifier.IOC_LOOKUP }
            .flatMap { matcher -> matcher.values.mapNotNull { it?.toString() } }
            .toSet()

        for (stubKey in iocStubs.keys) {
            if (stubKey !in referencedLookupNames) {
                errors.add(
                    "WARNING: iocStub key \"$stubKey\" is not referenced by any " +
                        "IOC_LOOKUP matcher in rule \"${rule.id}\". This may be a fixture typo."
                )
            }
        }

        // Guard: at least one TP record is required to prevent vacuous pass
        if (truePositives.isEmpty()) {
            errors.add("No true-positive records provided — fixture must include at least one TP")
            return Gate4Result(pass = false, tpFired = false, tnClean = true, errors = errors)
        }

        val allTpFired = evaluateFixtures(
            rule = rule,
            records = truePositives,
            iocLookups = iocLookups,
            errors = errors,
            label = "TP",
            shouldFire = true,
        )
        val allTnClean = evaluateFixtures(
            rule = rule,
            records = trueNegatives,
            iocLookups = iocLookups,
            errors = errors,
            label = "TN",
            shouldFire = false,
        )

        return Gate4Result(
            pass = allTpFired && allTnClean,
            tpFired = allTpFired,
            tnClean = allTnClean,
            errors = errors
        )
    }

    /**
     * Evaluates [records] against [rule]. When [shouldFire] is true, each record
     * must produce a triggered finding (true-positive semantics); when false,
     * each must produce no triggered finding (true-negative semantics — a
     * safe-state finding is fine). Records that violate the expectation are
     * reported in [errors] with the given [label]. Returns true if every record
     * behaved as expected.
     */
    @Suppress("LongParameterList")
    private fun evaluateFixtures(
        rule: SigmaRule,
        records: List<Map<String, Any?>>,
        iocLookups: Map<String, (Any) -> Boolean>,
        errors: MutableList<String>,
        label: String,
        shouldFire: Boolean,
    ): Boolean {
        var allPassed = true
        records.forEachIndexed { index, record ->
            val findings = SigmaRuleEvaluator.evaluate(
                rules = listOf(rule),
                records = listOf(record),
                service = rule.service,
                iocLookups = iocLookups
            )
            // A `report_safe_state: true` rule ALWAYS emits a finding — a
            // safe-state one with triggered=false — so presence of a finding is
            // not "fired". Count only genuinely-triggered findings; this also
            // makes such rules' true-positives non-vacuous (they must actually
            // trigger, not merely emit their safe-state row).
            val fired = findings.any { it.triggered }
            if (fired != shouldFire) {
                allPassed = false
                errors.add(
                    if (shouldFire) {
                        "$label[$index] FAILED: expected a triggered finding but got none for " +
                            "rule \"${rule.id}\". Record: $record"
                    } else {
                        "$label[$index] FAILED: expected no triggered finding but the rule fired " +
                            "for \"${rule.id}\". Record: $record"
                    }
                )
            }
        }
        return allPassed
    }
}
