package com.androdr.sigma

import android.content.Context
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.TelemetrySource
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class SigmaRuleEngineDisabledRuleTest {

    private val mockContext = mockk<Context>(relaxed = true)
    private lateinit var engine: SigmaRuleEngine

    private fun rule(id: String, enabled: Boolean = true) = SigmaRule(
        id = id, title = "Rule $id", status = "production", description = "",
        product = "androdr", service = "app_scanner", level = "high",
        category = RuleCategory.INCIDENT,
        tags = emptyList(),
        detection = SigmaDetection(
            selections = mapOf(
                "selection" to SigmaSelection(
                    fieldMatchers = listOf(
                        SigmaFieldMatcher(
                            fieldName = "is_system_app",
                            modifier = SigmaModifier.EQUALS,
                            values = listOf(false),
                        )
                    )
                )
            ),
            condition = "selection",
        ),
        falsepositives = emptyList(), remediation = emptyList(),
        enabled = enabled,
    )

    private val testTelemetry = AppTelemetry(
        packageName = "com.test.app",
        appName = "Test App",
        certHash = null,
        apkHash = null,
        isSystemApp = false,
        fromTrustedStore = false,
        installer = null,
        isSideloaded = true,
        isKnownOemApp = false,
        permissions = emptyList(),
        surveillancePermissionCount = 0,
        hasAccessibilityService = false,
        hasDeviceAdmin = false,
        knownAppCategory = null,
        source = TelemetrySource.LIVE_SCAN,
    )

    @Before
    fun setUp() {
        engine = SigmaRuleEngine(mockContext)
    }

    @Test
    fun `enabled rule produces finding when telemetry matches`() {
        val rules = listOf(rule("rule-enabled", enabled = true))
        setBundledRulesDirectly(rules)

        val findings = engine.evaluateApps(listOf(testTelemetry))

        assertEquals(1, findings.size)
        assertEquals("rule-enabled", findings[0].ruleId)
    }

    @Test
    fun `disabled rule produces no findings even when telemetry matches`() {
        val rules = listOf(rule("rule-disabled", enabled = false))
        setBundledRulesDirectly(rules)

        val findings = engine.evaluateApps(listOf(testTelemetry))

        assertTrue(
            "Expected no findings from disabled rule, got: ${findings.map { it.ruleId }}",
            findings.isEmpty(),
        )
    }

    @Test
    fun `mixed enabled and disabled rules only enabled ones fire`() {
        val rules = listOf(
            rule("rule-on-1", enabled = true),
            rule("rule-off", enabled = false),
            rule("rule-on-2", enabled = true),
        )
        setBundledRulesDirectly(rules)

        val findings = engine.evaluateApps(listOf(testTelemetry))

        assertEquals(2, findings.size)
        val firedIds = findings.map { it.ruleId }.toSet()
        assertEquals(setOf("rule-on-1", "rule-on-2"), firedIds)
    }

    @Test
    fun `disabled atom rule does not contribute to correlation bindings`() {
        val disabledAtom = SigmaRule(
            id = "atom-disabled",
            title = "Disabled atom",
            status = "production",
            description = "",
            product = "androdr",
            service = "test",
            level = "informational",
            category = RuleCategory.INCIDENT,
            tags = emptyList(),
            detection = SigmaDetection(
                selections = mapOf(
                    "selection" to SigmaSelection(
                        fieldMatchers = listOf(
                            SigmaFieldMatcher(
                                fieldName = "category",
                                modifier = SigmaModifier.EQUALS,
                                values = listOf("test_category"),
                            )
                        )
                    )
                ),
                condition = "selection",
            ),
            falsepositives = emptyList(),
            remediation = emptyList(),
            enabled = false,
        )

        setBundledRulesDirectly(listOf(disabledAtom))

        val method = SigmaRuleEngine::class.java.getDeclaredMethod(
            "computeAtomBindings",
            List::class.java,
        )
        method.isAccessible = true
        val event = com.androdr.data.model.ForensicTimelineEvent(
            startTimestamp = 0L,
            source = "test",
            category = "test_category",
            description = "test event",
        )
        @Suppress("UNCHECKED_CAST")
        val bindings = method.invoke(engine, listOf(event)) as Map<Long, Set<String>>

        assertTrue(
            "Expected no bindings from disabled atom rule, got: $bindings",
            bindings.values.flatten().isEmpty(),
        )
    }

    // Mirrors the pattern used in SigmaRuleEngineTest — sets both "bundledRules"
    // and "rules" fields so that effectiveRules() (which calls getRules() -> rules)
    // sees the injected list.
    private fun setBundledRulesDirectly(rules: List<SigmaRule>) {
        for (field in listOf("bundledRules", "rules")) {
            val f = SigmaRuleEngine::class.java.getDeclaredField(field)
            f.isAccessible = true
            f.set(engine, rules)
        }
    }
}
