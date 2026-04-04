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
        val bundled = listOf(rule("androdr-010", "Bundled 010"), rule("androdr-011", "Bundled 011"))
        setBundledRulesDirectly(bundled)

        val remote = listOf(rule("androdr-010", "Updated 010"))
        engine.setRemoteRules(remote)

        val rules = engine.getRules()
        assertEquals("Updated 010", rules.first { it.id == "androdr-010" }.title)
        assertEquals("Bundled 011", rules.first { it.id == "androdr-011" }.title)
    }

    @Test
    fun `remote rule adds new rules not in bundled set`() {
        setBundledRulesDirectly(listOf(rule("androdr-010")))

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
        setBundledRulesDirectly(bundled)

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

    @Test
    fun `repeated setRemoteRules does not inflate rule list`() {
        setBundledRulesDirectly(listOf(rule("androdr-010"), rule("androdr-011")))

        val remote = listOf(rule("androdr-010", "Updated"), rule("androdr-070", "New"))
        engine.setRemoteRules(remote)
        val countAfterFirst = engine.getRules().size

        engine.setRemoteRules(remote)
        val countAfterSecond = engine.getRules().size

        assertEquals(countAfterFirst, countAfterSecond)
        assertEquals(3, countAfterSecond) // 2 bundled + 1 new remote
    }

    @Test
    fun `loadBundledRules is idempotent`() {
        val bundled = listOf(rule("androdr-010", "Bundled"))
        setBundledRulesDirectly(bundled)

        val remote = listOf(rule("androdr-010", "Updated"))
        engine.setRemoteRules(remote)
        assertEquals("Updated", engine.getRules().first { it.id == "androdr-010" }.title)

        // Second loadBundledRules should be no-op, not wipe remote rules
        engine.loadBundledRules()
        assertEquals("Updated", engine.getRules().first { it.id == "androdr-010" }.title)
    }

    private fun setBundledRulesDirectly(rules: List<SigmaRule>) {
        for (field in listOf("bundledRules", "rules")) {
            val f = SigmaRuleEngine::class.java.getDeclaredField(field)
            f.isAccessible = true
            f.set(engine, rules)
        }
    }
}
