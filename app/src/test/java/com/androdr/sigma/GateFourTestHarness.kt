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
     * @param truePositives  Records that MUST produce at least one finding.
     * @param trueNegatives  Records that MUST produce zero findings.
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

        // Evaluate true positives — each must produce >= 1 finding.
        var allTpFired = true
        truePositives.forEachIndexed { index, record ->
            val findings = SigmaRuleEvaluator.evaluate(
                rules = listOf(rule),
                records = listOf(record),
                service = rule.service,
                iocLookups = iocLookups
            )
            if (findings.isEmpty()) {
                allTpFired = false
                errors.add(
                    "TP[$index] FAILED: expected >= 1 finding but got 0 for rule \"${rule.id}\". " +
                        "Record: $record"
                )
            }
        }

        // Evaluate true negatives — each must produce 0 findings.
        var allTnClean = true
        trueNegatives.forEachIndexed { index, record ->
            val findings = SigmaRuleEvaluator.evaluate(
                rules = listOf(rule),
                records = listOf(record),
                service = rule.service,
                iocLookups = iocLookups
            )
            if (findings.isNotEmpty()) {
                allTnClean = false
                errors.add(
                    "TN[$index] FAILED: expected 0 findings but got ${findings.size} " +
                        "for rule \"${rule.id}\". Record: $record"
                )
            }
        }

        return Gate4Result(
            pass = allTpFired && allTnClean,
            tpFired = allTpFired,
            tnClean = allTnClean,
            errors = errors
        )
    }
}
