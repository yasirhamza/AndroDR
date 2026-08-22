package com.androdr.sigma

import android.content.Context
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.TelemetrySource
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkEvaluationTest {

    private val mockContext = mockk<Context>(relaxed = true)

    private fun connect(ip: String, port: Int, pkg: String?) = NetworkTelemetry(
        destinationIp = ip, destinationPort = port, protocol = null,
        appUid = -1, appName = pkg, timestamp = 1787400345540L,
        source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
    )

    @Test
    fun `toFieldMap exposes taxonomy keys`() {
        val fields = connect("34.160.125.113", 443, "com.example").toFieldMap()
        assertEquals("34.160.125.113", fields["destination_ip"])
        assertEquals(443, fields["destination_port"])
        assertEquals(null, fields["protocol"])
        assertEquals("INTRUSION_LOG_IMPORT", fields["source"])
    }

    @Test
    fun `network_monitor rule fires on destination port`() {
        val ruleYaml = """
            title: ADB over TCP connect
            id: androdr-test-net
            status: experimental
            description: Test
            category: incident
            logsource:
                product: androdr
                service: network_monitor
            detection:
                selection:
                    destination_port: 5555
                condition: selection
            level: medium
            tags:
                - attack.t1021
        """.trimIndent()
        val rule = SigmaRuleParser.parse(ruleYaml)!!
        val records = listOf(
            connect("192.168.1.7", 5555, "com.evil").toFieldMap(),
            connect("142.250.200.163", 443, "com.google.android.gms").toFieldMap(),
        )
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(rule), records, "network_monitor", emptyMap(), emptyMap()
        )
        assertEquals(1, findings.count { it.triggered })
    }

    @Test
    fun `engine evaluateNetwork routes through network_monitor service`() {
        // Method existence + service-string test: an engine with zero rules
        // returns no findings but must not throw.
        val engine = SigmaRuleEngine(mockContext)
        assertTrue(engine.evaluateNetwork(listOf(connect("1.2.3.4", 80, null))).isEmpty())
    }
}
