package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Dual-gate cross-check (#136 R1, spec B5): every `logsource-taxonomy.yml`
 * field must declare whether it is a raw observed fact or an app-side
 * judgment call, and the set of judgment-marked field names must exactly
 * equal the frozen set that `judgment-field-allowlist.yml` declares via its
 * TOP-LEVEL KEYS (that file's own header: "the TOP-LEVEL KEYS are the
 * authoritative frozen judgment-field set ... both validators assert it").
 * `validate-rule.py` asserts the same equality on the rules-repo side; this
 * test independently gates the pinned submodule state so neither guard can
 * silently become the only one (#268 doctrine). Phase 3 of the strangler-fig
 * plan deletes a judgment field's allowlist key entirely — this test reads
 * the frozen set from that file rather than hardcoding it, so it keeps
 * passing across that deletion with no test-code edit.
 */
class TaxonomyJudgmentCrossCheckTest {

    @Test
    fun `every taxonomy field declares kind raw_fact or judgment`() {
        val taxonomy = TestRuleRepo.loadTaxonomy()
        assumeTrue("submodule not checked out — skipping", taxonomy != null)
        requireNotNull(taxonomy)

        val failures = mutableListOf<String>()
        for ((service, entry) in taxonomy) {
            for (field in entry.fields) {
                val kind = entry.fieldKinds[field]
                if (kind != "raw_fact" && kind != "judgment") {
                    failures += "$service.$field: kind is '${kind ?: "<missing>"}', expected " +
                        "'raw_fact' or 'judgment'"
                }
            }
        }

        assertTrue(
            "Taxonomy judgment-kind cross-check (#136 R1) failed — every field must declare " +
                "kind: raw_fact or kind: judgment:\n" +
                failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }

    @Test
    fun `judgment-marked field names equal the judgment-field-allowlist frozen set`() {
        val taxonomy = TestRuleRepo.loadTaxonomy()
        val allowlist = TestRuleRepo.judgmentAllowlist()
        assumeTrue("submodule not checked out — skipping", taxonomy != null && allowlist != null)
        requireNotNull(taxonomy)
        requireNotNull(allowlist)

        val judgmentFields = taxonomy.values
            .flatMap { service -> service.fieldKinds.filterValues { it == "judgment" }.keys }
            .toSet()
        val allowlistFields = allowlist.keys

        val markedButNotAllowlisted = judgmentFields - allowlistFields
        val allowlistedButNotMarked = allowlistFields - judgmentFields

        assertTrue(
            "Judgment field-name sets must match exactly between the taxonomy (kind: judgment) " +
                "and judgment-field-allowlist.yml's top-level keys.\n" +
                "Taxonomy judgment fields: ${judgmentFields.sorted()}\n" +
                "Allowlist top-level keys: ${allowlistFields.sorted()}\n" +
                "Marked judgment in taxonomy but missing from allowlist: " +
                "${markedButNotAllowlisted.sorted()}\n" +
                "Present in allowlist but not marked judgment in taxonomy: " +
                "${allowlistedButNotMarked.sorted()}",
            markedButNotAllowlisted.isEmpty() && allowlistedButNotMarked.isEmpty(),
        )
    }
}
