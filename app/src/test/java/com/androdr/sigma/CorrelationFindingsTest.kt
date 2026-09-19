package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A correlation signal -- a chain of events such as a sideloaded install followed by
 * a device-admin grant -- becomes a [Finding] in the scan that produced it (#350).
 * Until now it lived only as a timeline row: no severity, no effect on overall
 * risk, absent from the report's findings section. [CorrelationFindings] is the one
 * place that mapping happens.
 */
class CorrelationFindingsTest {

    private val rule = CorrelationRule(
        id = "androdr-corr-001",
        title = "Sideloaded install followed by device admin grant",
        type = CorrelationType.TEMPORAL_ORDERED,
        referencedRuleIds = listOf("androdr-atom-package-install", "androdr-atom-device-admin-grant"),
        timespanMs = 3_600_000L,
        groupBy = listOf("package_name"),
        minEvents = 1,
        severity = "high",
        displayLabel = "Install then device admin grant",
        description = "Detects an install event followed by a device admin grant on the same package.",
        tags = listOf("attack.t1626", "attack.t1098"),
    )

    private val signal = ForensicTimelineEvent(
        scanResultId = 42L,
        startTimestamp = 1_700_000_000_000L,
        endTimestamp = 1_700_000_600_000L,
        kind = "signal",
        category = "correlation",
        source = "sigma_correlation_engine",
        description = rule.displayLabel,
        details = """{"correlation_type":"temporal_ordered","rule_id":"androdr-corr-001","member_event_ids":"11,12"}""",
        packageName = "com.evil.app",
        ruleId = rule.id,
        correlationId = "androdr-corr-001:11,12",
    )

    @Test
    fun `maps a signal to a CORRELATION finding carrying the rule's label, description and tags`() {
        val finding = CorrelationFindings.fromSignal(signal, rule, RuleCategory.INCIDENT)

        assertEquals(FindingCategory.CORRELATION, finding.category)
        assertEquals("androdr-corr-001", finding.ruleId)
        assertEquals("Install then device admin grant", finding.title)
        assertEquals(rule.description, finding.description)
        assertEquals(rule.tags, finding.tags)
        assertTrue(finding.triggered)
    }

    @Test
    fun `severity follows the rule when the chain is an incident`() {
        val finding = CorrelationFindings.fromSignal(signal, rule, RuleCategory.INCIDENT)

        assertEquals("high", finding.level)
    }

    @Test
    fun `severity is capped when every leg of the chain is device posture`() {
        // Same policy as every other finding: a condition cannot out-shout an incident.
        val finding = CorrelationFindings.fromSignal(signal, rule, RuleCategory.DEVICE_POSTURE)

        assertEquals("medium", finding.level)
    }

    @Test
    fun `match context carries the package and the span of the chain`() {
        val ctx = CorrelationFindings.fromSignal(signal, rule, RuleCategory.INCIDENT).matchContext

        assertEquals("com.evil.app", ctx["package_name"])
        assertEquals("androdr-corr-001:11,12", ctx["correlation_id"])
        assertEquals("11,12", ctx["member_event_ids"])
        assertEquals("1700000000000", ctx["chain_start"])
        assertEquals("1700000600000", ctx["chain_end"])
    }
}
