package com.androdr.sigma

import android.content.Context
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityLogEvaluationTest {

    private val mockContext = mockk<Context>(relaxed = true)

    private fun event(tagName: String, data: List<String>) = SecurityLogEvent(
        timestamp = 1787400345540L, tag = 210002, tagName = tagName,
        securityData = data, source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
    )

    @Test
    fun `security_log rule fires on tag_name`() {
        val ruleYaml = """
            title: ADB shell command observed
            id: androdr-test-sec
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: security_log
            detection:
                selection:
                    tag_name: adb_shell_cmd
                condition: selection
            level: low
            tags:
                - attack.t1059
        """.trimIndent()
        val rule = SigmaRuleParser.parse(ruleYaml)!!
        val records = listOf(
            event("adb_shell_cmd", listOf("pm install /data/local/tmp/x.apk")).toFieldMap(),
            event("keyguard_dismissed", emptyList()).toFieldMap(),
        )
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), records, "security_log", emptyMap(), emptyMap()
        )
        assertEquals(1, findings.count { it.triggered })
    }

    @Test
    fun `engine evaluateSecurityLog exists and tolerates empty rules`() {
        val engine = SigmaRuleEngine(mockContext)
        assertTrue(engine.evaluateSecurityLog(listOf(event("adb_shell_cmd", emptyList()))).isEmpty())
    }
}
