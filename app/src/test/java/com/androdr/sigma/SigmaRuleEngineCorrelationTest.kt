package com.androdr.sigma

import android.content.Context
import io.mockk.mockk
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
}
