package com.androdr.cellular

import com.androdr.sigma.SigmaRuleParser
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A finding's title becomes the timeline row's description, and the
 * exporters print that as it is — only `details` is redacted. The evaluator
 * resolves `{field}` placeholders in `display.triggeredTitle` against every
 * scalar in the record, so a cellular rule that writes `{tac}` into its
 * title would put the tower straight into a shared report. No bundled
 * cellular rule may name an identity field in exported free text.
 *
 * The monitor also guards at runtime (CellularMonitor.safeDescription) for
 * remote and custom rules; this test keeps the bundled set honest at build
 * time, before the guard is needed.
 */
class CellularRuleTitleTemplatesTest {

    private val identityFields = listOf(
        "tac", "ci", "pci", "mcc", "mnc",
        "operator_alpha_long", "operator_alpha_short", "additional_plmns",
        "previous_tac", "sim_mcc", "sim_mnc", "sim_operator_name", "neighbor_pcis",
    )

    private fun rulesDirectory(): File = listOf(
        File("app/src/main/res/raw"),
        File("src/main/res/raw"),
    ).firstOrNull { it.isDirectory } ?: error("Could not locate res/raw")

    private fun cellularRules() = rulesDirectory()
        .listFiles { f -> f.name.startsWith("sigma_androdr_") && f.name.endsWith(".yml") }!!
        .mapNotNull { f -> SigmaRuleParser.parse(f.readText())?.let { f.name to it } }
        .filter { (_, rule) -> rule.service == "cellular_monitor" }

    @Test
    fun `no bundled cellular rule interpolates tower identity into exported text`() {
        val rules = cellularRules()
        assertTrue("no cellular rules found — is the filter right?", rules.isNotEmpty())
        val offenders = rules.flatMap { (name, rule) ->
            val texts = listOf(rule.title, rule.display.triggeredTitle, rule.display.safeTitle, rule.display.guidance) +
                rule.remediation
            identityFields.filter { field -> texts.any { it.contains("{$field}") } }.map { "$name uses {$it}" }
        }
        assertTrue("tower identity in exported free text:\n${offenders.joinToString("\n")}", offenders.isEmpty())
    }
}
