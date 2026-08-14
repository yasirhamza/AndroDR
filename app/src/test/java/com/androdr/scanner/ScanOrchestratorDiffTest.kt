package com.androdr.scanner

import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.UNREGISTERED_IOC_LOOKUP
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * [ScanOrchestrator.computeDiff] must never read a SKIPPED rule (unresolvable
 * `ioc_lookup` — see [SigmaRuleEngine.unevaluableRules]) as "resolved". A
 * skipped rule and a genuinely-un-triggered rule look identical in
 * [ScanResult.findings] (neither produces an entry unless the rule declares
 * `reportSafeState`), so the two are told apart by the capability-skip entries
 * the scan itself persisted: [ScannerFailure]s with
 * `exception == UNREGISTERED_IOC_LOOKUP`, each carrying a structured
 * [ScannerFailure.ruleId] (message text is never parsed).
 *
 * That makes computeDiff a PURE function of its two arguments — it consults no
 * live engine state. These tests pin that: the engine mock is stubbed to report
 * NOTHING skipped (the cold-start reality — a process that has not run a scan
 * yet has not registered its lookups) while the scan snapshots carry real skip
 * entries, and the fail-closed behavior must still hold.
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
        // Cold start: the engine knows of no skips. Every test below relies on
        // the persisted snapshots alone, so this stub must never matter.
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

    /** A capability-skip entry exactly as `recordRuleCapabilitySkips` writes it. */
    private fun skip(ruleId: String?): ScannerFailure =
        ScannerFailure(
            scanner = "ruleCapability",
            exception = UNREGISTERED_IOC_LOOKUP,
            message = "rule $ruleId not evaluated on this build: unregistered ioc_lookup 'x_db'",
            ruleId = ruleId
        )

    private fun scan(
        id: Long,
        findings: List<Finding>,
        scannerErrors: List<ScannerFailure> = emptyList()
    ): ScanResult =
        ScanResult(
            id = id,
            timestamp = id,
            findings = findings,
            bugReportFindings = emptyList(),
            riskySideloadCount = 0,
            knownMalwareCount = 0,
            scannerErrors = scannerErrors
        )

    @Test
    fun `a rule that triggered previously and is now skipped is never reported as resolved`() {
        // Skipped rules produce no Finding entry at all in the newer scan —
        // identical, absent-wise, to a rule that genuinely stopped triggering.
        val older = scan(1L, listOf(finding("androdr-999", triggered = true)))
        val newer = scan(2L, listOf(), scannerErrors = listOf(skip("androdr-999")))

        val diff = orchestrator.computeDiff(newer, older)

        assertFalse(
            "A skipped rule must never appear in resolvedFindings — that's false reassurance",
            diff.resolvedFindings.any { it.ruleId == "androdr-999" }
        )
    }

    @Test
    fun `the skip set comes from the newer scan, not from live engine state`() {
        val older = scan(1L, listOf(finding("androdr-999", triggered = true)))
        val newer = scan(2L, listOf(), scannerErrors = listOf(skip("androdr-999")))

        val diff = orchestrator.computeDiff(newer, older)

        assertFalse(diff.resolvedFindings.any { it.ruleId == "androdr-999" })
        // Purity: no engine round-trip at all. A diff rendered at cold start
        // (History opened before any scan ran in this process) must be correct
        // from persisted data alone.
        verify(exactly = 0) { sigmaRuleEngine.unevaluableRules() }
    }

    @Test
    fun `a rule that genuinely stops triggering (not skipped) IS resolved`() {
        val older = scan(1L, listOf(finding("androdr-010", triggered = true)))
        val newer = scan(2L, listOf())

        val diff = orchestrator.computeDiff(newer, older)

        assertTrue(diff.resolvedFindings.any { it.ruleId == "androdr-010" })
    }

    @Test
    fun `unrelated triggered findings are unaffected by the skipped-id set`() {
        val older = scan(
            1L,
            listOf(finding("androdr-999", triggered = true), finding("androdr-010", triggered = true))
        )
        // Both absent this scan: -999 skipped, -010 genuinely resolved.
        val newer = scan(2L, listOf(), scannerErrors = listOf(skip("androdr-999")))

        val diff = orchestrator.computeDiff(newer, older)

        assertFalse(diff.resolvedFindings.any { it.ruleId == "androdr-999" })
        assertTrue(diff.resolvedFindings.any { it.ruleId == "androdr-010" })
    }

    @Test
    fun `a real scanner failure does not suppress resolution`() {
        // Only UNREGISTERED_IOC_LOOKUP entries feed the skip set. A crashed
        // scanner already raises the partial-scan banner; it must not also
        // freeze the diff (and it names no rule).
        val older = scan(1L, listOf(finding("androdr-010", triggered = true)))
        val newer = scan(
            2L, listOf(),
            scannerErrors = listOf(
                ScannerFailure(scanner = "appScanner", exception = "IllegalStateException", message = "boom")
            )
        )

        val diff = orchestrator.computeDiff(newer, older)

        assertTrue(diff.resolvedFindings.any { it.ruleId == "androdr-010" })
    }

    @Test
    fun `legacy skip entries without a ruleId contribute nothing - documented compat limit`() {
        // Rows persisted before ScannerFailure.ruleId existed carry null. They
        // cannot suppress anything (there is no id to suppress) — pinned here so
        // the limitation stays a known compat gap rather than a silent surprise.
        val older = scan(1L, listOf(finding("androdr-999", triggered = true)))
        val newer = scan(2L, listOf(), scannerErrors = listOf(skip(ruleId = null)))

        val diff = orchestrator.computeDiff(newer, older)

        assertTrue(diff.resolvedFindings.any { it.ruleId == "androdr-999" })
    }

    @Test
    fun `newly triggered findings are reported as new`() {
        val older = scan(1L, listOf())
        val newer = scan(2L, listOf(finding("androdr-010", triggered = true)))

        val diff = orchestrator.computeDiff(newer, older)

        assertTrue(diff.newFindings.any { it.ruleId == "androdr-010" })
        assertTrue(diff.resolvedFindings.isEmpty())
    }
}
