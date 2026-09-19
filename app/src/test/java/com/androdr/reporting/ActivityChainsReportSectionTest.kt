package com.androdr.reporting

import com.androdr.data.model.ScanResult
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Correlation findings get their own report section, ahead of device checks and app
 * risks, because a chain of events is the strongest evidence the app produces (#350).
 * The user-facing name is deliberately not "correlation": that is the internal
 * category. See [ReportFormatter.CHAINS_SECTION].
 */
class ActivityChainsReportSectionTest {

    private val chain = Finding(
        ruleId = "androdr-corr-001",
        title = "Install then device admin grant",
        description = "An app installed from outside the store was granted device-admin power soon after.",
        level = "high",
        category = FindingCategory.CORRELATION,
        triggered = true,
        tags = listOf("attack.t1626"),
        matchContext = mapOf("package_name" to "com.evil.app", "member_event_ids" to "11,12"),
    )
    private val appRisk = Finding(
        ruleId = "androdr-010", title = "Sideloaded Application", level = "medium",
        category = FindingCategory.APP_RISK, triggered = true,
        matchContext = mapOf("package_name" to "com.evil.app"),
    )
    private val posture = Finding(
        ruleId = "androdr-040", title = "USB Debugging Enabled", level = "medium",
        category = FindingCategory.DEVICE_POSTURE, triggered = true,
    )

    private fun scanOf(vararg findings: Finding) = ScanResult(
        id = 1L, timestamp = 1711900800000, findings = findings.toList(), bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, scannerErrors = emptyList(),
    )

    private fun report(scan: ScanResult) =
        ReportFormatter.formatScanReport(
            scan, emptyList(), emptyList(), versionName = "test", mode = ExportMode.FINDINGS_ONLY,
        )

    @Test
    fun `chains section is rendered before device checks and app risks`() {
        val text = report(scanOf(chain, appRisk, posture))

        val chains = text.indexOf(ReportFormatter.CHAINS_SECTION)
        val device = text.indexOf("DEVICE CHECKS")
        val apps = text.indexOf("APP RISKS")
        assertTrue("chains section missing", chains >= 0)
        assertTrue("chains must come before DEVICE CHECKS", chains < device)
        assertTrue("chains must come before APP RISKS", chains < apps)
    }

    @Test
    fun `a chain is rendered in its section with its label, package and severity`() {
        val text = report(scanOf(chain))
        val section = text.substring(text.indexOf(ReportFormatter.CHAINS_SECTION), text.indexOf("DEVICE CHECKS"))

        assertTrue(section.contains("Install then device admin grant"))
        assertTrue(section.contains("com.evil.app"))
        assertTrue(section.contains("HIGH"))
        assertTrue(section.contains(chain.description))
    }

    @Test
    fun `a chain is not also listed under app risks or device checks`() {
        val text = report(scanOf(chain))
        val afterDevice = text.substring(text.indexOf("DEVICE CHECKS"))

        assertEquals("chain leaked into a later section", -1, afterDevice.indexOf("Install then device admin grant"))
    }

    @Test
    fun `the section says so when there are no chains`() {
        val text = report(scanOf(appRisk))

        assertTrue(text.contains(ReportFormatter.CHAINS_SECTION))
        assertTrue(text.contains("No suspicious activity chains detected"))
    }

    @Test
    fun `the summary names the chains and the action list points at the app`() {
        val text = report(scanOf(chain))
        val summary = text.substring(0, text.indexOf(ReportFormatter.CHAINS_SECTION))

        assertTrue("summary should count the chains", summary.contains("Suspicious activity chains: 1"))
        assertTrue("action guidance should name the app", summary.contains("com.evil.app"))
    }

    @Test
    fun `the user-facing name is not the internal category`() {
        assertTrue(!ReportFormatter.CHAINS_SECTION.contains("CORRELATION"))
    }
}
