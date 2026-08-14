package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Dual-gate cross-check (#136 R1, spec B3): `validation/severity-caps.yml` is
 * the single declared source for per-rule-category severity caps. Both
 * `validate-rule.py` (rules-repo PR gate) and [SeverityCapPolicy] (on-device
 * enforcement) are supposed to agree with it; this test independently gates
 * the pinned submodule state against the Kotlin runtime so neither guard can
 * silently become the only one (#268 doctrine).
 *
 * The YAML's keys are RULE categories — [RuleCategory]'s `incident` /
 * `device_posture` vocabulary — NOT display categories (`app_risk` /
 * `device_posture` / `network`, [SigmaDisplay.category] /
 * `FindingCategory`'s vocabulary, which drives UI grouping, not severity
 * clamping). The two vocabularies happen to share the string
 * `device_posture`, which is exactly why a stray display-category key here
 * must fail loud rather than silently resolve (or silently fail to resolve)
 * against the wrong enum.
 */
class SeverityCapsCrossCheckTest {

    @Test
    fun `every declared cap key is a real RuleCategory and matches SeverityCapPolicy`() {
        val caps = TestRuleRepo.severityCaps()
        assumeTrue("submodule not checked out — skipping", caps != null)
        requireNotNull(caps)

        val ruleCategoryVocab = RuleCategory.entries.joinToString("|") { it.name.lowercase() }
        val failures = mutableListOf<String>()

        for ((key, cappedSeverity) in caps) {
            val category = try {
                RuleCategory.valueOf(key.uppercase())
            } catch (e: IllegalArgumentException) {
                failures += "severity-caps.yml key '$key' is not a RuleCategory " +
                    "(RuleCategory.valueOf threw: ${e.message}). Caps are keyed by RULE " +
                    "categories ($ruleCategoryVocab) — a distinct vocabulary from DISPLAY " +
                    "categories (app_risk|device_posture|network, SigmaDisplay.category / " +
                    "FindingCategory), which drive UI grouping, not severity clamping."
                continue
            }
            val actual = SeverityCapPolicy.applyCap(category, "critical")
            if (actual != cappedSeverity) {
                failures += "severity-caps.yml declares $key: $cappedSeverity but " +
                    "SeverityCapPolicy.applyCap($category, \"critical\") returned '$actual' — " +
                    "SeverityCapPolicy has drifted from the declared cap"
            }
        }

        assertTrue(
            "Severity-caps cross-check (#136 R1) failed:\n" +
                failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }

    @Test
    fun `categories absent from severity-caps yml remain uncapped in SeverityCapPolicy`() {
        val caps = TestRuleRepo.severityCaps()
        assumeTrue("submodule not checked out — skipping", caps != null)
        requireNotNull(caps)

        val declaredCategories = caps.keys.mapNotNull {
            runCatching { RuleCategory.valueOf(it.uppercase()) }.getOrNull()
        }.toSet()

        val failures = mutableListOf<String>()
        for (category in RuleCategory.entries) {
            if (category in declaredCategories) continue
            val actual = SeverityCapPolicy.applyCap(category, "critical")
            if (actual != "critical") {
                failures += "$category is absent from severity-caps.yml (uncapped) but " +
                    "SeverityCapPolicy.applyCap($category, \"critical\") returned '$actual' " +
                    "instead of passing 'critical' through unchanged"
            }
        }

        assertTrue(
            "Uncapped-category cross-check (#136 R1) failed:\n" +
                failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }
}
