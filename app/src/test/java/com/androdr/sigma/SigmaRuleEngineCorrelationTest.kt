package com.androdr.sigma

import android.content.Context
import com.androdr.data.model.ForensicTimelineEvent
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class SigmaRuleEngineCorrelationTest {

    private val mockContext = mockk<Context>(relaxed = true)
    private lateinit var engine: SigmaRuleEngine

    @Before
    fun setUp() {
        engine = SigmaRuleEngine(mockContext)
    }

    @Test
    fun `loadCorrelationRules throws UnresolvedRule when referenced rule is missing`() {
        // No detection rules loaded; rules list is empty.
        val corr = CorrelationRule(
            id = "androdr-corr-missing",
            title = "Missing ref",
            type = CorrelationType.TEMPORAL,
            referencedRuleIds = listOf("androdr-atom-does-not-exist"),
            timespanMs = 60_000L,
            groupBy = emptyList(),
            minEvents = 1,
            severity = "medium",
            displayLabel = "Missing ref",
            displayCategory = "correlation"
        )

        assertTrue(engine.getCorrelationRules().isEmpty())

        assertThrows(CorrelationParseException.UnresolvedRule::class.java) {
            engine.loadCorrelationRules(listOf(corr))
        }

        // Validate-then-assign: state must not be mutated on failure.
        assertTrue(engine.getCorrelationRules().isEmpty())
    }

    @Test
    fun `computeAtomBindings maps events to atom rule ids by category`() {
        val atomInstall = atomRule("androdr-atom-package-install", "package_install")
        val atomAdmin = atomRule("androdr-atom-device-admin-grant", "device_admin_grant")
        // Inject atom rules via setRemoteRules — bundledRules is empty, so
        // the merged list equals the supplied rules.
        engine.setRemoteRules(listOf(atomInstall, atomAdmin))

        val events = listOf(
            event(id = 1, category = "package_install"),
            event(id = 2, category = "device_admin_grant"),
            event(id = 3, category = "dns_lookup") // no matching atom
        )

        val bindings = engine.computeAtomBindings(events)

        assertEquals(setOf("androdr-atom-package-install"), bindings[1])
        assertEquals(setOf("androdr-atom-device-admin-grant"), bindings[2])
        assertEquals(emptySet<String>(), bindings[3])
    }

    private fun atomRule(
        id: String,
        category: String,
        ruleCategory: RuleCategory = RuleCategory.INCIDENT,
    ): SigmaRule = SigmaRule(
        id = id,
        title = id,
        status = "production",
        description = "",
        product = "androdr",
        service = "timeline",
        level = "informational",
        category = ruleCategory,
        tags = emptyList(),
        detection = SigmaDetection(
            selections = mapOf(
                "selection" to SigmaSelection(
                    fieldMatchers = listOf(
                        SigmaFieldMatcher(
                            fieldName = "category",
                            modifier = SigmaModifier.EQUALS,
                            values = listOf(category)
                        )
                    )
                )
            ),
            condition = "selection"
        ),
        falsepositives = emptyList(),
        remediation = emptyList()
    )

    private fun event(id: Long, category: String): ForensicTimelineEvent =
        ForensicTimelineEvent(
            id = id,
            scanResultId = 1L,
            startTimestamp = id * 1000L,
            kind = "event",
            category = category,
            source = "test",
            description = "test",
            severity = "info"
        )
}
