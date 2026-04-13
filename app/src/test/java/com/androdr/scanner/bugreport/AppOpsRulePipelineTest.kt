package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import com.androdr.sigma.SigmaRuleEvaluator
import com.androdr.sigma.SigmaRuleParser
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Verifies that AppOpsModule telemetry format matches what SIGMA rules expect.
 * Catches dialect mismatches (e.g., "CAMERA" vs "android:camera") at the
 * module→rule boundary.
 */
class AppOpsRulePipelineTest {

    private val mockIndicatorResolver: IndicatorResolver = mockk()
    private lateinit var module: AppOpsModule

    // Actual SIGMA rule YAML matching what ships in res/raw
    private val cameraRuleYaml = """
        title: Non-system app accessed camera
        id: androdr-064
        status: production
        description: test
        author: test
        date: 2026/01/01
        category: incident
        tags:
            - attack.t1429
        logsource:
            product: androdr
            service: appops_audit
        detection:
            selection:
                operation: "android:camera"
                is_system_app: false
            condition: selection
        level: medium
        display:
            category: app_risk
    """.trimIndent()

    private val micRuleYaml = """
        title: Non-system app accessed microphone
        id: androdr-063
        status: production
        description: test
        author: test
        date: 2026/01/01
        category: incident
        tags:
            - attack.t1429
        logsource:
            product: androdr
            service: appops_audit
        detection:
            selection:
                operation: "android:record_audio"
                is_system_app: false
            condition: selection
        level: medium
        display:
            category: app_risk
    """.trimIndent()

    private val installRuleYaml = """
        title: Non-system app used install packages
        id: androdr-065
        status: production
        description: test
        author: test
        date: 2026/01/01
        category: incident
        tags:
            - attack.t1407
        logsource:
            product: androdr
            service: appops_audit
        detection:
            selection:
                operation: "android:request_install_packages"
                is_system_app: false
            condition: selection
        level: high
        display:
            category: app_risk
    """.trimIndent()

    @Before
    fun setUp() {
        every { mockIndicatorResolver.isKnownBadPackage(any()) } returns null
        module = AppOpsModule()
    }

    @Test
    fun `module camera output triggers camera SIGMA rule`() = runBlocking {
        val section = """
            Uid 10200:
              Package com.suspicious.app:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        val rule = SigmaRuleParser.parse(cameraRuleYaml)!!
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), result.telemetry, "appops_audit"
        )
        assertTrue(
            "AppOpsModule camera output must trigger androdr-064 rule — " +
                "check operation name format matches between module and rule",
            findings.any { it.triggered && it.ruleId == "androdr-064" }
        )
    }

    @Test
    fun `module microphone output triggers microphone SIGMA rule`() = runBlocking {
        val section = """
            Uid 10200:
              Package com.suspicious.app:
                RECORD_AUDIO (allow):
                  Access: [fg-s] 2026-03-27 14:35:00
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        val rule = SigmaRuleParser.parse(micRuleYaml)!!
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), result.telemetry, "appops_audit"
        )
        assertTrue(
            "AppOpsModule mic output must trigger androdr-063 rule — " +
                "check operation name format matches between module and rule",
            findings.any { it.triggered && it.ruleId == "androdr-063" }
        )
    }

    @Test
    fun `module install packages output triggers install SIGMA rule`() = runBlocking {
        val section = """
            Uid 10200:
              Package com.suspicious.installer:
                REQUEST_INSTALL_PACKAGES (allow):
                  Access: [fg-s] 2026-03-27 14:40:00
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        val rule = SigmaRuleParser.parse(installRuleYaml)!!
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), result.telemetry, "appops_audit"
        )
        assertTrue(
            "AppOpsModule install output must trigger androdr-065 rule — " +
                "check operation name format matches between module and rule",
            findings.any { it.triggered && it.ruleId == "androdr-065" }
        )
    }

    @Test
    fun `system app camera usage does not trigger rule`() = runBlocking {
        val section = """
            Uid 1000:
              Package com.android.systemui:
                CAMERA (allow):
                  Access: [fg-s] 2026-03-27 14:30:00
        """.trimIndent()

        val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
        val rule = SigmaRuleParser.parse(cameraRuleYaml)!!
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), result.telemetry, "appops_audit"
        )
        assertTrue(
            "System app camera usage must not trigger rule",
            findings.none { it.triggered }
        )
    }

    @Test
    fun `all dangerous ops normalize to android colon lowercase format`() = runBlocking {
        val allOps = listOf(
            "CAMERA", "RECORD_AUDIO", "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
            "READ_CONTACTS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION",
            "READ_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES"
        )

        for (op in allOps) {
            val section = """
                Uid 10200:
                  Package com.test.app:
                    $op (allow):
                      Access: [fg-s] 2026-03-27 14:30:00
            """.trimIndent()

            val result = module.analyze(section, mockIndicatorResolver, com.androdr.ioc.DeviceIdentity.UNKNOWN)
            val telemetry = result.telemetry.first()
            val operation = telemetry["operation"] as String

            assertTrue(
                "Operation '$op' must normalize to 'android:${op.lowercase()}' " +
                    "but was '$operation'",
                operation == "android:${op.lowercase()}"
            )
        }
    }
}
