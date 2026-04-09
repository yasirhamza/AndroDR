package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Test

class SigmaCorrelationEngineCategoryPropagationTest {

    private val engine = SigmaCorrelationEngine()

    private fun makeAtomRule(id: String, category: RuleCategory) = SigmaRule(
        id = id, title = "Atom $id", status = "production", description = "",
        product = "androdr", service = "test", level = "high",
        category = category,
        tags = emptyList(),
        detection = SigmaDetection(emptyMap(), "selection"),
        falsepositives = emptyList(), remediation = emptyList()
    )

    @Test
    fun `correlation with one incident member propagates INCIDENT`() {
        val atoms = mapOf(
            "atom-1" to makeAtomRule("atom-1", RuleCategory.INCIDENT),
            "atom-2" to makeAtomRule("atom-2", RuleCategory.DEVICE_POSTURE),
        )
        val effective = engine.computeEffectiveCategory(
            referencedRuleIds = listOf("atom-1", "atom-2"),
            atomRulesById = atoms,
        )
        assertEquals(RuleCategory.INCIDENT, effective)
    }

    @Test
    fun `correlation with only device_posture members propagates DEVICE_POSTURE`() {
        val atoms = mapOf(
            "atom-1" to makeAtomRule("atom-1", RuleCategory.DEVICE_POSTURE),
            "atom-2" to makeAtomRule("atom-2", RuleCategory.DEVICE_POSTURE),
        )
        val effective = engine.computeEffectiveCategory(
            referencedRuleIds = listOf("atom-1", "atom-2"),
            atomRulesById = atoms,
        )
        assertEquals(RuleCategory.DEVICE_POSTURE, effective)
    }

    @Test
    fun `correlation with only incident members is INCIDENT`() {
        val atoms = mapOf(
            "atom-1" to makeAtomRule("atom-1", RuleCategory.INCIDENT),
            "atom-2" to makeAtomRule("atom-2", RuleCategory.INCIDENT),
        )
        val effective = engine.computeEffectiveCategory(
            referencedRuleIds = listOf("atom-1", "atom-2"),
            atomRulesById = atoms,
        )
        assertEquals(RuleCategory.INCIDENT, effective)
    }

    @Test
    fun `correlation with one known and one unknown member uses category from known`() {
        val atoms = mapOf(
            "atom-1" to makeAtomRule("atom-1", RuleCategory.DEVICE_POSTURE),
        )
        val effective = engine.computeEffectiveCategory(
            referencedRuleIds = listOf("atom-1", "atom-missing"),
            atomRulesById = atoms,
        )
        assertEquals(RuleCategory.DEVICE_POSTURE, effective)
    }

    @Test
    fun `correlation referencing all unknown rules defaults to INCIDENT`() {
        val atoms = mapOf<String, SigmaRule>()
        val effective = engine.computeEffectiveCategory(
            referencedRuleIds = listOf("atom-missing-1", "atom-missing-2"),
            atomRulesById = atoms,
        )
        assertEquals(RuleCategory.INCIDENT, effective)
    }
}
