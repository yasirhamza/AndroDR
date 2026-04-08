package com.androdr.sigma

import org.junit.Assert.*
import org.junit.Test

class SigmaRuleParserCorrelationTest {

    private fun parser() = SigmaRuleParser()

    @Test
    fun `parses temporal_ordered rule`() {
        val yaml = """
            title: Install then admin
            id: androdr-corr-001
            correlation:
                type: temporal_ordered
                rules:
                    - androdr-atom-package-install
                    - androdr-atom-device-admin-grant
                timespan: 1h
                group-by:
                    - package_name
            display:
                category: correlation
                severity: high
                label: "Install then admin"
        """.trimIndent()
        val rule = parser().parseCorrelation(yaml)
        assertEquals("androdr-corr-001", rule.id)
        assertEquals(CorrelationType.TEMPORAL_ORDERED, rule.type)
        assertEquals(2, rule.referencedRuleIds.size)
        assertEquals(3600_000L, rule.timespanMs)
        assertEquals("package_name", rule.groupBy.single())
    }

    @Test
    fun `parses event_count rule with gte condition`() {
        val yaml = """
            title: Burst
            id: androdr-corr-004
            correlation:
                type: event_count
                rules: [androdr-atom-permission-use]
                timespan: 5m
                group-by: [package_name]
                condition:
                    gte: 3
            display:
                category: correlation
                severity: high
                label: "Burst"
        """.trimIndent()
        val rule = parser().parseCorrelation(yaml)
        assertEquals(CorrelationType.EVENT_COUNT, rule.type)
        assertEquals(3, rule.minEvents)
        assertEquals(300_000L, rule.timespanMs)
    }

    @Test(expected = CorrelationParseException.UnsupportedType::class)
    fun `value_count rejected at parse time`() {
        parser().parseCorrelation("""
            title: T
            id: x
            correlation:
                type: value_count
                rules: [a]
                timespan: 1h
                condition: { gte: 1 }
        """.trimIndent())
    }

    @Test(expected = CorrelationParseException.TimespanExceeded::class)
    fun `timespan exceeding 90 days rejected`() {
        parser().parseCorrelation("""
            title: T
            id: x
            correlation:
                type: temporal_ordered
                rules: [a, b]
                timespan: 91d
        """.trimIndent())
    }

    @Test(expected = CorrelationParseException.InvalidGrammar::class)
    fun `missing rules list rejected`() {
        parser().parseCorrelation("""
            title: T
            id: x
            correlation:
                type: temporal_ordered
                timespan: 1h
        """.trimIndent())
    }

    @Test
    fun `parses timespan in seconds, minutes, hours, days`() {
        fun span(s: String): Long = parser().parseCorrelation("""
            title: T
            id: x
            correlation:
                type: temporal_ordered
                rules: [a, b]
                timespan: $s
            display:
                category: correlation
                severity: high
                label: T
        """.trimIndent()).timespanMs

        assertEquals(45_000L, span("45s"))
        assertEquals(120_000L, span("2m"))
        assertEquals(7200_000L, span("2h"))
        assertEquals(86400_000L * 7, span("7d"))
    }
}
