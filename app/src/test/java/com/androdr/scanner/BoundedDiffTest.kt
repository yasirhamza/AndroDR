package com.androdr.scanner

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.repo.FindingsRepository
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Review Minor A: [ScanOrchestrator.boundedDiff] takes the not-evaluated skip set from the NEWER
 * scan. A rule the newer scan could not evaluate is not "resolved" even though only the older scan
 * triggered it (a skipped CRITICAL must never read as fixed).
 */
class BoundedDiffTest {

    private fun scan(id: Long, errors: List<ScannerFailure> = emptyList()) = ScanResult(id = id, timestamp = id,
        bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = errors)

    private fun skip(ruleId: String) = ScannerFailure(scanner = "coverage",
        exception = NotEvaluatedReason.MISSING_CAPABILITY.sentinel, message = ruleId, ruleId = ruleId)

    private fun finding(ruleId: String) =
        Finding(ruleId = ruleId, title = ruleId, level = "critical", category = FindingCategory.APP_RISK)

    @Test
    fun `a rule the newer scan skipped is not resolved, the skip set is read from the newer scan`() = runBlocking {
        val findings = mockk<FindingsRepository>()
        coEvery { findings.triggeredRuleCounts(2L) } returns emptyMap()
        coEvery { findings.triggeredRuleCounts(1L) } returns mapOf("skipped" to 2, "fixed" to 1)
        coEvery { findings.ruleSample(1L, any(), any()) } answers { listOf(finding(secondArg())) }
        val newer = scan(2L, listOf(skip("skipped")))
        val older = scan(1L, listOf(skip("fixed")))

        val diff = ScanOrchestrator.boundedDiff(findings, newer, older)

        assertEquals(listOf("fixed"), diff.resolvedFindings.map { it.ruleId })
        assertEquals(1, diff.resolvedCount)
        assertEquals(0, diff.newCount)
    }
}
