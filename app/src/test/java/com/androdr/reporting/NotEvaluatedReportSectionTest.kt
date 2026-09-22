package com.androdr.reporting

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A check that did not run has to appear in the report.
 *
 * Until now only one kind did: a rule naming an ioc_lookup the build lacks. Two
 * others were silent, and both produced a report that read like a clean result --
 * the CRITICAL artifact rule whose paths no unprivileged app can read (#366), and
 * the chain rules whose legs need events nothing recorded (#370). The reader could
 * not tell "checked and clear" from "never checked".
 */
class NotEvaluatedReportSectionTest {

    private fun scanWith(vararg errors: ScannerFailure) = ScanResult(
        id = 1L, timestamp = 1711900800000, findings = emptyList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = errors.toList(),
    )

    private fun report(scan: ScanResult) = ReportFormatter.formatScanReport(
        scan, emptyList(), emptyList(), versionName = "test", mode = ExportMode.FINDINGS_ONLY,
    )

    private val missingCapability = ScannerFailure(
        "ruleCapability", NotEvaluatedReason.MISSING_CAPABILITY.sentinel,
        "rule androdr-001 not evaluated on this build: unregistered ioc_lookup 'foo'", "androdr-001",
    )
    private val unreadablePaths = ScannerFailure(
        "fileArtifactScanner", NotEvaluatedReason.UNREADABLE_PATHS.sentinel,
        "Known spyware artifact (androdr-020): 13 of 13 path(s) could not be read on this device",
        "androdr-020",
    )
    private val noEvents = ScannerFailure(
        "correlation", NotEvaluatedReason.NO_EVENTS_TO_CHECK.sentinel,
        "Surveillance burst (androdr-corr-004): needs records of apps using sensitive permissions " +
            "(only an imported bug report carries these), none recorded in this scan",
        "androdr-corr-004",
    )

    @Test
    fun `a scan that checked everything says nothing about limits`() {
        val text = report(scanWith())

        assertFalse(text.contains(ReportFormatter.NOT_CHECKED_SECTION))
    }

    @Test
    fun `the critical artifact rule the device refused is named, with its reason`() {
        val text = report(scanWith(unreadablePaths))

        assertTrue(text.contains(ReportFormatter.NOT_CHECKED_SECTION))
        assertTrue(text.contains(NotEvaluatedReason.UNREADABLE_PATHS.heading))
        assertTrue("the rule must be named", text.contains("androdr-020"))
        assertTrue("the count must survive", text.contains("13 of 13"))
    }

    @Test
    fun `a chain rule with nothing to check is named, and says where the evidence comes from`() {
        val text = report(scanWith(noEvents))

        assertTrue(text.contains(ReportFormatter.NOT_CHECKED_SECTION))
        assertTrue(text.contains(NotEvaluatedReason.NO_EVENTS_TO_CHECK.heading))
        assertTrue(text.contains("androdr-corr-004"))
        assertTrue("the reader needs to know an import supplies it", text.contains("bug report"))
    }

    @Test
    fun `reasons are grouped under their own headings, in a fixed order`() {
        val text = report(scanWith(noEvents, unreadablePaths, missingCapability))

        val capability = text.indexOf(NotEvaluatedReason.MISSING_CAPABILITY.heading)
        val unreadable = text.indexOf(NotEvaluatedReason.UNREADABLE_PATHS.heading)
        val nothing = text.indexOf(NotEvaluatedReason.NO_EVENTS_TO_CHECK.heading)

        assertTrue("every reason must have a heading", capability >= 0 && unreadable >= 0 && nothing >= 0)
        assertTrue("order follows the enum, not the error list", capability < unreadable)
        assertTrue("order follows the enum, not the error list", unreadable < nothing)
    }

    @Test
    fun `a scanner that crashed is not dressed up as a check that could not run`() {
        val text = report(scanWith(ScannerFailure("appScanner", "IllegalStateException", "boom")))

        assertFalse("a crash belongs to the partial-scan banner", text.contains(ReportFormatter.NOT_CHECKED_SECTION))
    }

    @Test
    fun `the warning-signs section points at patterns that could not be checked`() {
        val text = report(scanWith(noEvents))

        val chainsBlock = text.substring(
            text.indexOf(ReportFormatter.WARNING_SIGNS_SECTION),
            text.indexOf("DEVICE CHECKS"),
        )
        assertTrue(
            "an empty chains section must not imply every pattern was checked: $chainsBlock",
            chainsBlock.contains("could not be checked"),
        )
    }
}
