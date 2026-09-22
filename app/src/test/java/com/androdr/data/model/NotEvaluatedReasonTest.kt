package com.androdr.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A rule that was never evaluated is not a scanner that failed.
 *
 * The build already knew one such reason -- a rule naming an ioc_lookup this
 * binary does not register -- and excluded it from the partial-scan banner by
 * comparing against one magic string. Two more reasons exist and were silent:
 * artifact paths no unprivileged app can read (#366) and correlation rules whose
 * events nothing produced (#370). Each new reason compared by hand is a chance
 * to forget one and turn accepted under-detection into a scary "scan failed"
 * banner, so the reasons are enumerated and the count derives from the
 * enumeration.
 */
class NotEvaluatedReasonTest {

    private fun scan(vararg errors: ScannerFailure) =
        ScanResult(timestamp = 0L, findings = emptyList(), bugReportFindings = emptyList(),
            riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = errors.toList())

    @Test
    fun `every declared reason is accepted under-detection, not a failure`() {
        NotEvaluatedReason.entries.forEach { reason ->
            val result = scan(ScannerFailure("scanner", reason.sentinel, "why", ruleId = "androdr-001"))

            assertEquals("${reason.name} must not count as a failure", 0, result.realFailureCount)
            assertFalse("${reason.name} must not raise the partial-scan banner", result.isPartialScan)
        }
    }

    @Test
    fun `a scanner that actually crashed still raises the banner`() {
        val result = scan(ScannerFailure("appScanner", "IllegalStateException", "boom"))

        assertEquals(1, result.realFailureCount)
        assertTrue(result.isPartialScan)
    }

    @Test
    fun `crashes and skips are counted apart`() {
        val result = scan(
            ScannerFailure("appScanner", "IllegalStateException", "boom"),
            ScannerFailure("fileArtifactScanner", NotEvaluatedReason.UNREADABLE_PATHS.sentinel, "13 paths"),
            ScannerFailure("correlation", NotEvaluatedReason.NO_EVENTS_TO_CHECK.sentinel, "corr-004"),
        )

        assertEquals("only the crash is a failure", 1, result.realFailureCount)
    }

    @Test
    fun `the ioc-lookup sentinel keeps the string it has always been persisted as`() {
        // Scans on disk carry the old literal; changing it would silently turn
        // every stored capability skip back into a "scan failed" banner.
        assertEquals("UnregisteredIocLookup", NotEvaluatedReason.MISSING_CAPABILITY.sentinel)
        assertEquals(UNREGISTERED_IOC_LOOKUP, NotEvaluatedReason.MISSING_CAPABILITY.sentinel)
    }

    @Test
    fun `a reason is recoverable from the persisted string`() {
        NotEvaluatedReason.entries.forEach { reason ->
            assertEquals(reason, NotEvaluatedReason.fromSentinel(reason.sentinel))
        }
        assertEquals(null, NotEvaluatedReason.fromSentinel("SomethingElseEntirely"))
    }
}
