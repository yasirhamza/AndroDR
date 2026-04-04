package com.androdr.sigma

import android.content.Context
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class SigmaRuleEngineTest {

    private val mockContext = mockk<Context>(relaxed = true)
    private lateinit var engine: SigmaRuleEngine

    private fun rule(id: String, title: String = "Rule $id") = SigmaRule(
        id = id, title = title, status = "production", description = "",
        product = "androdr", service = "app_scanner", level = "high",
        tags = emptyList(),
        detection = SigmaDetection(emptyMap(), "selection"),
        falsepositives = emptyList(), remediation = emptyList()
    )

    @Before
    fun setUp() {
        engine = SigmaRuleEngine(mockContext)
    }

    @Test
    fun `remote rule replaces bundled rule with same ID`() {
        // Simulate bundled rules by setting them via reflection-free approach
        engine.setRemoteRules(emptyList()) // no-op, just init
        // Load "bundled" rules directly
        val bundled = listOf(rule("androdr-010", "Bundled 010"), rule("androdr-011", "Bundled 011"))
        setRulesDirectly(bundled)

        val remote = listOf(rule("androdr-010", "Updated 010"))
        engine.setRemoteRules(remote)

        val rules = engine.getRules()
        val rule010 = rules.first { it.id == "androdr-010" }
        assertEquals("Updated 010", rule010.title)
        assertEquals("Bundled 011", rules.first { it.id == "androdr-011" }.title)
    }

    @Test
    fun `remote rule adds new rules not in bundled set`() {
        setRulesDirectly(listOf(rule("androdr-010")))

        val remote = listOf(rule("androdr-070", "New remote rule"))
        engine.setRemoteRules(remote)

        val ids = engine.getRules().map { it.id }
        assertTrue("androdr-070" in ids)
        assertEquals(2, ids.size)
    }

    @Test
    fun `protected rules cannot be replaced by remote`() {
        val bundled = listOf(
            rule("androdr-001", "Bundled IOC"),
            rule("androdr-002", "Bundled cert"),
            rule("androdr-010", "Bundled sideload")
        )
        setRulesDirectly(bundled)

        val remote = listOf(
            rule("androdr-001", "Neutered IOC"),
            rule("androdr-002", "Neutered cert"),
            rule("androdr-010", "Updated sideload")
        )
        engine.setRemoteRules(remote)

        val rules = engine.getRules()
        assertEquals("Bundled IOC", rules.first { it.id == "androdr-001" }.title)
        assertEquals("Bundled cert", rules.first { it.id == "androdr-002" }.title)
        assertEquals("Updated sideload", rules.first { it.id == "androdr-010" }.title)
    }

    private fun setRulesDirectly(rules: List<SigmaRule>) {
        val field = SigmaRuleEngine::class.java.getDeclaredField("rules")
        field.isAccessible = true
        field.set(engine, rules)
    }
}
