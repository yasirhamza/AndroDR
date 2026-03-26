package com.androdr.ui.apps

import com.androdr.data.model.AppRisk
import com.androdr.data.model.RiskLevel
import org.junit.Assert.assertTrue
import org.junit.Test

class RemediationStepsTest {

    private fun risk(
        reasons: List<String> = emptyList(),
        isKnownMalware: Boolean = false,
        isSideloaded: Boolean = false
    ) = AppRisk(
        packageName = "com.test.app",
        appName = "Test",
        riskLevel = RiskLevel.HIGH,
        reasons = reasons,
        isKnownMalware = isKnownMalware,
        isSideloaded = isSideloaded,
        dangerousPermissions = emptyList()
    )

    @Test
    fun `known malware produces uninstall immediately step`() {
        val steps = remediationSteps(risk(isKnownMalware = true))
        assertTrue(steps.any { "Uninstall this app immediately" in it })
    }

    @Test
    fun `signing certificate reason produces developer warning`() {
        val steps = remediationSteps(risk(
            reasons = listOf("Known malicious signing certificate (Cerberus)")
        ))
        assertTrue(steps.any { "known malware developer" in it })
    }

    @Test
    fun `accessibility service reason produces disable instruction`() {
        val steps = remediationSteps(risk(
            reasons = listOf("Registered as an accessibility service")
        ))
        assertTrue(steps.any { "Accessibility" in it })
    }

    @Test
    fun `device administrator reason produces remove admin instruction`() {
        val steps = remediationSteps(risk(
            reasons = listOf("Registered as a device administrator")
        ))
        assertTrue(steps.any { "Device Admin" in it || "device administrator" in it.lowercase() })
    }

    @Test
    fun `surveillance permissions reason produces review instruction`() {
        val steps = remediationSteps(risk(
            reasons = listOf(
                "Holds 4 sensitive surveillance-capable permissions simultaneously: " +
                    "RECORD_AUDIO, CAMERA, ACCESS_FINE_LOCATION, READ_CONTACTS"
            )
        ))
        assertTrue(steps.any { "surveillance" in it.lowercase() })
    }

    @Test
    fun `sideloaded only produces verify instruction`() {
        val steps = remediationSteps(risk(
            isSideloaded = true,
            reasons = listOf("App was not installed via a trusted app store (installer: unknown)")
        ))
        assertTrue(steps.any { "trusted app store" in it.lowercase() || "not installed" in it.lowercase() })
    }

    @Test
    fun `always ends with run another scan step`() {
        val steps = remediationSteps(risk())
        assertTrue(steps.last().contains("scan"))
    }
}
