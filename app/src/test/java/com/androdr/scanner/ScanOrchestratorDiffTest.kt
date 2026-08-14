package com.androdr.scanner

import com.androdr.data.model.ScanResult
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * [ScanOrchestrator.computeDiff] must never read a SKIPPED rule (unresolvable
 * `ioc_lookup` — see [SigmaRuleEngine.unevaluableRules]) as "resolved". A
 * skipped rule and a genuinely-un-triggered rule look identical in
 * [ScanResult.findings] (neither produces an entry unless the rule declares
 * `reportSafeState`), so the only way to tell them apart is the separate
 * skipped-id set threaded through [ScanOrchestrator.computeDiff] — parsing
 * ids back out of [com.androdr.data.model.ScannerFailure] messages would be
 * fragile (no structured ruleId field) and is deliberately not done.
 *
 * Rendering a skipped CRITICAL finding as "resolved" is affirmative false
 * reassurance — worse than a silent miss.
 */
class ScanOrchestratorDiffTest {

    private lateinit var sigmaRuleEngine: SigmaRuleEngine
    private lateinit var orchestrator: ScanOrchestrator

    @Before
    fun setUp() {
        sigmaRuleEngine = mockk(relaxed = true)
        every { sigmaRuleEngine.unevaluableRules() } returns emptyMap()

        orchestrator = ScanOrchestrator(
            appScanner = mockk(relaxed = true),
            deviceAuditor = mockk(relaxed = true),
            processScanner = mockk(relaxed = true),
            fileArtifactScanner = mockk(relaxed = true),
            accessibilityAuditScanner = mockk(relaxed = true),
            receiverAuditScanner = mockk(relaxed = true),
            appOpsScanner = mockk(relaxed = true),
            usageStatsScanner = mockk(relaxed = true),
            bugReportAnalyzer = mockk(relaxed = true),
            scanRepository = mockk(relaxed = true),
            dnsEventDao = mockk(relaxed = true),
            forensicTimelineEventDao = mockk(relaxed = true),
            installEventEmitter = mockk(relaxed = true),
            deviceAdminGrantEmitter = mockk(relaxed = true),
            sigmaRuleEngine = sigmaRuleEngine,
            sigmaCorrelationEngine = mockk(relaxed = true),
            indicatorResolver = mockk(relaxed = true),
            sigmaRuleFeed = mockk(relaxed = true),
            knownAppResolver = mockk(relaxed = true),
            oemPrefixResolver = mockk(relaxed = true)
        )
    }

    private fun finding(ruleId: String, triggered: Boolean = true): Finding =
        Finding(ruleId = ruleId, title = ruleId, level = "critical", triggered = triggered)

    private fun scan(id: Long, findings: List<Finding>): ScanResult =
        ScanResult(
            id = id,
            timestamp = id,
            findings = findings,
            bugReportFindings = emptyList(),
            riskySideloadCount = 0,
            knownMalwareCount = 0
        )

    @Test
    fun `a rule that triggered previously and is now skipped is never reported as resolved`() {
        every { sigmaRuleEngine.unevaluableRules() } returns mapOf("androdr-999" to "trusted_installer_db")

        // Skipped rules produce no Finding entry at all in the newer scan —
        // identical, absent-wise, to a rule that genuinely stopped triggering.
        val older = scan(1L, listOf(finding("androdr-999", triggered = true)))
        val newer = scan(2L, listOf())

        val diff = orchestrator.computeDiff(newer, older)

        assertFalse(
            "A skipped rule must never appear in resolvedFindings — that's false reassurance",
            diff.resolvedFindings.any { it.ruleId == "androdr-999" }
        )
    }

    @Test
    fun `a rule that genuinely stops triggering (not skipped) IS resolved`() {
        every { sigmaRuleEngine.unevaluableRules() } returns emptyMap()

        val older = scan(1L, listOf(finding("androdr-010", triggered = true)))
        val newer = scan(2L, listOf())

        val diff = orchestrator.computeDiff(newer, older)

        assertTrue(diff.resolvedFindings.any { it.ruleId == "androdr-010" })
    }

    @Test
    fun `explicit skippedRuleIds argument overrides the engine default for direct testing`() {
        val older = scan(1L, listOf(finding("androdr-777", triggered = true)))
        val newer = scan(2L, listOf())

        val diff = orchestrator.computeDiff(newer, older, skippedRuleIds = setOf("androdr-777"))

        assertFalse(diff.resolvedFindings.any { it.ruleId == "androdr-777" })
    }

    @Test
    fun `unrelated triggered findings are unaffected by the skipped-id set`() {
        every { sigmaRuleEngine.unevaluableRules() } returns mapOf("androdr-999" to "trusted_installer_db")

        val older = scan(
            1L,
            listOf(finding("androdr-999", triggered = true), finding("androdr-010", triggered = true))
        )
        val newer = scan(2L, listOf()) // both absent this scan: -999 skipped, -010 genuinely resolved

        val diff = orchestrator.computeDiff(newer, older)

        assertFalse(diff.resolvedFindings.any { it.ruleId == "androdr-999" })
        assertTrue(diff.resolvedFindings.any { it.ruleId == "androdr-010" })
    }
}
