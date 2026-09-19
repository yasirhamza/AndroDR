package com.androdr.data.model

import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * [ScanResult.overallRiskLevel] must be a function of finding severity alone.
 *
 * The data model has two category concepts that must never be conflated:
 *
 *  - the rule's `category:` (incident | device_posture) declares whether a hit is
 *    something that HAPPENED or a CONDITION. It is the sole input to
 *    SeverityCapPolicy, which clamps posture findings to medium at creation time,
 *    so [Finding.level] already carries that decision;
 *  - `display.category` (app_risk | device_posture | ...) says which SECTION of the
 *    report or screen a finding is shown in. It is presentation.
 *
 * Before #364 the aggregation read the presentation field to decide what counted as
 * a condition, so any incident whose display bucket happened to be `device_posture`
 * — androdr-020, a critical spyware artifact on disk — was ceilinged at MEDIUM while
 * the same report listed it as CRITICAL. These tests pin the aggregation to severity
 * and to nothing else.
 */
class ScanResultOverallRiskTest {

    private fun finding(
        level: String,
        category: FindingCategory,
        triggered: Boolean = true,
        ruleId: String = "androdr-000",
    ) = Finding(
        ruleId = ruleId,
        title = "$ruleId ($level, $category)",
        level = level,
        category = category,
        triggered = triggered,
    )

    private fun scanOf(vararg findings: Finding) = ScanResult(
        id = 1L,
        timestamp = 1711900800000,
        findings = findings.toList(),
        bugReportFindings = emptyList(),
        riskySideloadCount = 0,
        knownMalwareCount = 0,
        scannerErrors = emptyList(),
    )

    /** androdr-020 exactly as it ships: `category: incident`, `level: critical`, shown under device posture. */
    @Test
    fun `critical incident displayed under device posture is CRITICAL`() {
        val artifact = finding("critical", FindingCategory.DEVICE_POSTURE, ruleId = "androdr-020")

        assertEquals(RiskLevel.CRITICAL, scanOf(artifact).overallRiskLevel)
    }

    /** The uniformity gate: swapping only the display bucket must never change the number. */
    @Test
    fun `display category does not influence overall risk`() {
        for (level in listOf("critical", "high", "medium", "low", "informational")) {
            val asAppRisk = scanOf(finding(level, FindingCategory.APP_RISK)).overallRiskLevel
            val asPosture = scanOf(finding(level, FindingCategory.DEVICE_POSTURE)).overallRiskLevel
            val asNetwork = scanOf(finding(level, FindingCategory.NETWORK)).overallRiskLevel

            assertEquals("level=$level: app_risk vs device_posture", asAppRisk, asPosture)
            assertEquals("level=$level: app_risk vs network", asAppRisk, asNetwork)
        }
    }

    /** androdr-072 persistent_wakelock: a `low` incident shown under device posture is LOW, not floored to MEDIUM. */
    @Test
    fun `low incident displayed under device posture is LOW`() {
        val wakelock = finding("low", FindingCategory.DEVICE_POSTURE, ruleId = "androdr-072")

        assertEquals(RiskLevel.LOW, scanOf(wakelock).overallRiskLevel)
    }

    /**
     * The 13 real `category: device_posture` rules all arrive at `medium` — either declared
     * so or clamped there by SeverityCapPolicy before the Finding exists. Their overall
     * contribution is therefore MEDIUM, exactly as before; the cap, not the aggregation,
     * is what keeps a condition from out-shouting an incident.
     */
    @Test
    fun `capped posture finding contributes MEDIUM`() {
        val adb = finding("medium", FindingCategory.DEVICE_POSTURE, ruleId = "androdr-040")

        assertEquals(RiskLevel.MEDIUM, scanOf(adb).overallRiskLevel)
    }

    @Test
    fun `overall risk is the maximum across all triggered findings`() {
        val scan = scanOf(
            finding("low", FindingCategory.APP_RISK),
            finding("high", FindingCategory.DEVICE_POSTURE),
            finding("medium", FindingCategory.APP_RISK),
        )

        assertEquals(RiskLevel.HIGH, scan.overallRiskLevel)
    }

    @Test
    fun `untriggered findings are ignored whatever their severity`() {
        val scan = scanOf(
            finding("critical", FindingCategory.APP_RISK, triggered = false),
            finding("critical", FindingCategory.DEVICE_POSTURE, triggered = false),
            finding("low", FindingCategory.APP_RISK),
        )

        assertEquals(RiskLevel.LOW, scan.overallRiskLevel)
    }

    @Test
    fun `no triggered findings is LOW`() {
        assertEquals(RiskLevel.LOW, scanOf().overallRiskLevel)
        assertEquals(
            RiskLevel.LOW,
            scanOf(finding("critical", FindingCategory.APP_RISK, triggered = false)).overallRiskLevel,
        )
    }
}
