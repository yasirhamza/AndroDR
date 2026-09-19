package com.androdr.reporting

import com.androdr.data.model.ScanResult
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The exported report and the in-app screens must state the same overall risk.
 *
 * They diverged in #70 (2026-04-05), which switched the report header to score the
 * first word of each rule's prose `display.guidance` while leaving every UI surface
 * on [ScanResult.overallRiskLevel]'s severity scores. Guidance became a severity
 * channel without becoming a validated one, so the header drifted in both
 * directions as the rule corpus grew (#332):
 *
 *  - over-reporting: one medium "REVIEW --" finding printed HIGH on a clean device;
 *  - under-reporting: a critical finding whose guidance is ordinary prose
 *    (androdr-094 BADBOX/MoYu) or absent (androdr-089) printed LOW.
 *
 * These tests pin the header to the single shared calculation.
 */
class OverallRiskConsistencyTest {

    private fun scanOf(vararg findings: Finding): ScanResult = ScanResult(
        id = 1L,
        timestamp = 1711900800000,
        findings = findings.toList(),
        bugReportFindings = emptyList(),
        riskySideloadCount = 0,
        knownMalwareCount = 0,
        scannerErrors = emptyList()
    )

    private fun headerRiskOf(scan: ScanResult): String =
        ReportFormatter.formatScanReport(scan, emptyList(), emptyList(), versionName = "test")
            .lineSequence()
            .first { it.contains("OVERALL RISK:") }
            .substringAfter("OVERALL RISK:")
            .trim()

    private fun appRisk(ruleId: String, level: String, guidance: String) = Finding(
        ruleId = ruleId,
        title = "$ruleId finding",
        level = level,
        category = FindingCategory.APP_RISK,
        triggered = true,
        guidance = guidance,
        matchContext = mapOf("package_name" to "com.example.$ruleId")
    )

    /** The live 0.9.0.627 field report: one review-grade WebAPK plus boot-persistence noise. */
    @Test
    fun `clean device with only review-grade and low findings does not report HIGH`() {
        val webApk = appRisk(
            "androdr-010",
            "medium",
            "REVIEW -- sideloaded app with elevated permissions; verify intentional"
        )
        val bootPersistence = (1..6).map {
            appRisk("androdr-066-$it", "low", "Review whether this app should start at boot")
        }

        val risk = headerRiskOf(scanOf(webApk, *bootPersistence.toTypedArray()))

        assertEquals("nothing above MEDIUM was found, so the header must not say HIGH", "MEDIUM", risk)
    }

    /** androdr-094 BADBOX/MoYu: critical, but its guidance is prose, so it scored zero. */
    @Test
    fun `critical finding whose guidance is prose is not reported as LOW`() {
        val badbox = appRisk(
            "androdr-094",
            "critical",
            "This app declares a service component matching MoYu Group's 'AdmoyuService' naming, " +
                "associated with the BADBOX zhima residential-proxy and ad-fraud malware."
        )

        val risk = headerRiskOf(scanOf(badbox))

        assertEquals("a critical malware detection must not print LOW", "CRITICAL", risk)
    }

    /** androdr-089 and seven siblings ship no `display.guidance` at all. */
    @Test
    fun `high finding with no guidance is not reported as LOW`() {
        val otpTheft = appRisk("androdr-089", "high", guidance = "")

        val risk = headerRiskOf(scanOf(otpTheft))

        assertEquals("a high-severity detection must not print LOW", "HIGH", risk)
    }

    /**
     * The structural gate: whatever the inputs, the report header and the value every
     * UI surface renders come from one calculation. A second ladder anywhere fails this.
     */
    @Test
    fun `report header always equals the scan's overall risk level`() {
        val corpus = listOf(
            scanOf(),
            scanOf(appRisk("androdr-094", "critical", "This app declares a service component...")),
            scanOf(appRisk("androdr-089", "high", "")),
            scanOf(appRisk("androdr-010", "medium", "REVIEW -- sideloaded app")),
            scanOf(appRisk("androdr-066", "low", "Review whether this preload is expected")),
            scanOf(appRisk("androdr-001", "critical", "UNINSTALL IMMEDIATELY -- known malware")),
            // A correlation chain, now a finding on the scan (#350).
            scanOf(
                Finding(
                    ruleId = "androdr-corr-004",
                    title = "Multiple permissions accessed rapidly",
                    level = "high",
                    category = FindingCategory.CORRELATION,
                    triggered = true,
                    matchContext = mapOf("package_name" to "com.example.burst")
                )
            ),
            // androdr-020: a critical INCIDENT whose display bucket is device posture (#364).
            scanOf(
                Finding(
                    ruleId = "androdr-020",
                    title = "Spyware artifact: /data/local/tmp/.raptor",
                    level = "critical",
                    category = FindingCategory.DEVICE_POSTURE,
                    triggered = true,
                    remediation = listOf("Do NOT delete it yet -- it may be needed as evidence.")
                )
            ),
            scanOf(
                Finding(
                    ruleId = "androdr-040",
                    title = "USB Debugging Enabled",
                    level = "high",
                    category = FindingCategory.DEVICE_POSTURE,
                    triggered = true,
                    remediation = listOf("Disable USB debugging")
                )
            )
        )

        corpus.forEach { scan ->
            assertEquals(
                "header disagrees with ScanResult.overallRiskLevel for ${scan.findings.map { it.ruleId }}",
                scan.overallRiskLevel.name,
                headerRiskOf(scan)
            )
        }
    }
}
