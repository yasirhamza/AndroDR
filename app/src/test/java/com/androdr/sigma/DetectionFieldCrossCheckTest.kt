package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Dead-rule gate (#268), second guard: every rule's `detection:` block must be
 * evaluable on-device exactly as authored. The primary guard is
 * `validate-rule.py` in the rules repo (gating rules-repo main, which the app
 * fetches every 12h); this test independently gates the pinned-submodule state
 * so neither guard can silently become the only one.
 *
 * The taxonomy at the pinned submodule
 * (`validation/logsource-taxonomy.yml`) is CANONICAL: if a rule and the
 * taxonomy disagree, the rule is wrong. Taxonomy changes land only via a
 * rules-repo PR + submodule bump (see the taxonomy's SAFE ORDERING header).
 *
 * Two surfaces, same assertions:
 *  (a) every bundled `sigma_androdr_*.yml` in res/raw;
 *  (b) every rules.txt-listed file from the pinned submodule — nothing asserts
 *      rules.txt ⊆ bundled and res/raw is cold-start-only by design, so a
 *      remote-only rule would otherwise be gated by validate-rule.py alone.
 *
 * The threat is bidirectional. A typo'd field in a positive selection means
 * the evaluator's missing-field null-guard returns false forever — the rule
 * ships, loads, evaluates, and can never fire. The same typo inside a NEGATED
 * filter selection means the filter never subtracts and the rule fires on
 * everything (e.g. androdr-011's `filter_known_good` guarding OEM preloads).
 * Enumerate the current blast radius with:
 * `grep -l "not filter" app/src/main/res/raw/sigma_androdr_*.yml`
 *
 * Beyond field membership this asserts, per rule:
 *  - every parsed selection has ≥1 matcher (an emptied selection is vacuously
 *    TRUE, `SigmaRuleEvaluator` `.all{}` on an empty list);
 *  - every matcher has a non-empty value list (empty/null lists are
 *    constant-false, or vacuously TRUE for standalone `|all`);
 *  - the condition matches the device evaluator's grammar
 *    `["not"] name (("and"|"or") ["not"] name)*` with every name resolving to
 *    a PARSED selection — this catches selections the parser silently dropped
 *    (non-mapping bodies), whose names evaluate `?: false` (dead positive /
 *    over-firing negated filter);
 *  - the service exists in the taxonomy and is `status: active`. No staging
 *    carve-out is needed: rules.txt never lists staging paths, an invariant
 *    gated on both sides (BundledMirrorParityTest; the rules repo's
 *    delivery-set check).
 *
 * Known residual reliance: a field key whose only matcher is `|re` with all
 * patterns over the parser's length cap is dropped at parse time and invisible
 * to this walk, and uncompilable `|re` patterns are constant-false at runtime —
 * both are gated by validate-rule.py's raw-YAML checks, tied to the bundled
 * set via BundledMirrorParityTest.
 *
 * Second, unrelated gate riding the same walk (#136 R1, spec B5): a detection
 * base-field whose taxonomy `kind` is `judgment` (see
 * `TaxonomyJudgmentCrossCheckTest`) may only be referenced by a rule id listed
 * in `judgment-field-allowlist.yml`'s `delivered` list for that field — both
 * surfaces this test walks (bundled res/raw and rules.txt) are "delivered" in
 * that file's sense. `validate-rule.py` asserts the same allowlist on the
 * rules-repo side; this is the independent AndroDR-side guard so neither can
 * silently become the only one.
 */
class DetectionFieldCrossCheckTest {

    private val yamlLoader = Load(LoadSettings.builder().build())

    @Suppress("LoopWithTooManyJumpStatements")
    // Token state-machine: the guard continues are clearer than flag-based restructuring.
    private fun checkConditionGrammar(
        condition: String,
        selectionNames: Set<String>,
    ): List<String> {
        // Tokenizer pinned to the evaluator via TestRuleRepo.conditionTokens.
        // Do NOT normalize parentheses: the evaluator has no paren handling,
        // and mirroring validate-rule.py's historical stripping here would
        // re-open that divergence.
        val tokens = TestRuleRepo.conditionTokens(condition)
        if (tokens.isEmpty()) return listOf("empty condition — rule is dead on-device")
        val errors = mutableListOf<String>()
        var expectOperand = true
        var i = 0
        while (i < tokens.size) {
            var tok = tokens[i]
            var low = tok.lowercase()
            if (expectOperand) {
                if (low == "not") {
                    i++
                    if (i >= tokens.size) {
                        errors += "dangling 'not' — negation silently dropped on-device (over-fires)"
                        break
                    }
                    tok = tokens[i]
                    low = tok.lowercase()
                }
                if (low in TestRuleRepo.CONDITION_KEYWORDS) {
                    errors += "keyword '$tok' where a selection name was expected — " +
                        "the evaluator consumes it as an operand (?: false)"
                    break
                }
                if (tok !in selectionNames) {
                    errors += "condition references '$tok' but no parsed selection has that " +
                        "name — it evaluates ?: false (dead positive / over-firing negated filter)"
                }
                expectOperand = false
                i++
            } else {
                if (low == "and" || low == "or") {
                    expectOperand = true
                    i++
                } else {
                    errors += "expected 'and'/'or' before '$tok' — the device grammar is " +
                        "[\"not\"] name ((\"and\"|\"or\") [\"not\"] name)* with no parentheses"
                    break
                }
            }
        }
        if (errors.isEmpty() && expectOperand) {
            errors += "condition ends with a dangling operator"
        }
        return errors
    }

    /**
     * B5's judgment-field gate for a single matcher, split out of [checkRuleFile]
     * purely to keep that function's length in bounds — same failure-message
     * style, same [failures] sink.
     */
    private fun checkJudgmentFieldUsage(
        file: File,
        selName: String,
        matcher: SigmaFieldMatcher,
        ruleId: String,
        fieldKind: String?,
        judgmentAllowlist: Map<String, TestRuleRepo.JudgmentFieldAllowance>,
        failures: MutableList<String>,
    ) {
        if (fieldKind != "judgment") return
        val allowedIds = judgmentAllowlist[matcher.fieldName]?.delivered
        if (allowedIds == null) {
            failures += "${file.name}: selection '$selName' matches judgment field " +
                "'${matcher.fieldName}' which has no entry at all in " +
                "judgment-field-allowlist.yml — no rule may reference it until it is allowlisted"
        } else if (ruleId !in allowedIds) {
            failures += "${file.name}: selection '$selName' matches judgment field " +
                "'${matcher.fieldName}' but rule id '$ruleId' is not in " +
                "judgment-field-allowlist.yml's delivered list for that field " +
                "(allowed: ${allowedIds.sorted()})"
        }
    }

    /** Per-matcher checks (dead field, empty value list, B5's judgment-field gate),
     *  split out of [checkRuleFile] purely to keep that function's length in bounds. */
    private fun checkMatcher(
        file: File,
        selName: String,
        matcher: SigmaFieldMatcher,
        rule: SigmaRule,
        service: TestRuleRepo.TaxonomyService,
        judgmentAllowlist: Map<String, TestRuleRepo.JudgmentFieldAllowance>,
        failures: MutableList<String>,
    ) {
        if (matcher.fieldName !in service.fields) {
            failures += "${file.name}: selection '$selName' matches field " +
                "'${matcher.fieldName}' which service '${rule.service}' does not " +
                "provide — dead field (valid: ${service.fields.sorted()})"
        }
        if (matcher.values.isEmpty()) {
            failures += "${file.name}: selection '$selName' field " +
                "'${matcher.fieldName}' has an empty value list — constant-false " +
                "matcher (vacuously TRUE for standalone |all)"
        }
        checkJudgmentFieldUsage(
            file,
            selName,
            matcher,
            rule.id,
            service.fieldKinds[matcher.fieldName],
            judgmentAllowlist,
            failures,
        )
    }

    @Suppress("UNCHECKED_CAST", "ReturnCount")
    // Guard-clause early returns are clearer than nested branches for these parse/taxonomy failure paths.
    private fun checkRuleFile(
        file: File,
        taxonomy: Map<String, TestRuleRepo.TaxonomyService>,
        judgmentAllowlist: Map<String, TestRuleRepo.JudgmentFieldAllowance>,
        failures: MutableList<String>,
    ) {
        val text = file.readText()

        // Correlation docs must never reach this walk: surface (a) excludes
        // them by filename, surface (b) by delivery policy. Assert the
        // content-level invariant loudly instead of silently routing.
        val raw = yamlLoader.loadFromString(text) as? Map<String, Any?>
        if (raw == null) {
            failures += "${file.name}: YAML did not parse to a map"
            return
        }
        if (raw.containsKey("correlation")) {
            failures += "${file.name}: contains a top-level 'correlation:' key but was swept " +
                "as a detection rule — naming/delivery drift (corr rules are excluded by " +
                "the sigma_androdr_corr_ prefix on res/raw and by rules.txt policy upstream)"
            return
        }

        val rule = SigmaRuleParser.parse(text)
        if (rule == null) {
            failures += "${file.name}: SigmaRuleParser.parse returned null — the rule is " +
                "silently dropped on-device"
            return
        }

        val service = taxonomy[rule.service]
        if (service == null) {
            failures += "${file.name}: service '${rule.service}' is not in the taxonomy " +
                "(valid: ${taxonomy.keys.sorted()})"
            return
        }
        if (service.status != "active") {
            failures += "${file.name}: service '${rule.service}' has taxonomy status " +
                "'${service.status}' — the engine cannot evaluate it; the rule is dead"
        }

        for ((selName, selection) in rule.detection.selections) {
            if (selection.fieldMatchers.isEmpty()) {
                failures += "${file.name}: selection '$selName' parsed to zero matchers — " +
                    "vacuously TRUE on-device (over-fires positively, kills the rule under 'not')"
                continue
            }
            for (matcher in selection.fieldMatchers) {
                checkMatcher(file, selName, matcher, rule, service, judgmentAllowlist, failures)
            }
        }

        checkConditionGrammar(rule.detection.condition, rule.detection.selections.keys)
            .forEach { failures += "${file.name}: $it" }
    }

    @Test
    fun `every bundled rule detection block is evaluable against the taxonomy`() {
        val taxonomy = TestRuleRepo.loadTaxonomy()
        val judgmentAllowlist = TestRuleRepo.judgmentAllowlist()
        assumeTrue(
            "submodule not checked out — skipping",
            taxonomy != null && judgmentAllowlist != null,
        )
        requireNotNull(taxonomy)
        requireNotNull(judgmentAllowlist)

        val failures = mutableListOf<String>()
        TestRuleRepo.bundledRuleFiles().forEach {
            checkRuleFile(it, taxonomy, judgmentAllowlist, failures)
        }
        assertTrue(
            "Dead-rule gate (#268) failed for bundled rules:\n" +
                failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }

    @Test
    fun `every delivered rule detection block is evaluable against the taxonomy`() {
        val taxonomy = TestRuleRepo.loadTaxonomy()
        val delivered = TestRuleRepo.submoduleRuleFiles()
        val judgmentAllowlist = TestRuleRepo.judgmentAllowlist()
        assumeTrue(
            "submodule not checked out — skipping",
            taxonomy != null && delivered != null && judgmentAllowlist != null,
        )
        requireNotNull(taxonomy)
        requireNotNull(delivered)
        requireNotNull(judgmentAllowlist)

        val failures = mutableListOf<String>()
        delivered.forEach { checkRuleFile(it, taxonomy, judgmentAllowlist, failures) }
        assertTrue(
            "Dead-rule gate (#268) failed for rules.txt-delivered rules:\n" +
                failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }
}
