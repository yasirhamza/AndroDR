package com.androdr.cellular

import com.androdr.sigma.SigmaRuleEvaluator
import com.androdr.sigma.SigmaRuleParser
import org.junit.Assert.assertTrue
import org.junit.Test

class CellularEvaluationTest {

    private val narrowBandwidthRule = """
        title: Implausibly narrow cell bandwidth
        id: androdr-101
        status: experimental
        description: Test
        category: incident
        logsource:
            product: androdr
            service: cellular_monitor
        detection:
            selection:
                is_registered: true
                bandwidth_khz:
                    - 1400
                    - 3000
            condition: selection
        level: low
    """.trimIndent()

    @Test
    fun `cellular_monitor rule fires on narrow bandwidth`() {
        val rule = SigmaRuleParser.parse(narrowBandwidthRule)!!
        val narrow = mapOf<String, Any?>("is_registered" to true, "bandwidth_khz" to 1400)
        val wide = mapOf<String, Any?>("is_registered" to true, "bandwidth_khz" to 20000)

        val hit = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(narrow), "cellular_monitor", emptyMap(), emptyMap()
        )
        assertTrue("Should fire on 1.4 MHz", hit.any { it.triggered })

        val miss = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(wide), "cellular_monitor", emptyMap(), emptyMap()
        )
        assertTrue("Should not fire on 20 MHz", miss.none { it.triggered })
    }

    @Test
    fun `rules bound to another service do not fire on cellular records`() {
        val rule = SigmaRuleParser.parse(narrowBandwidthRule)!!
        val narrow = mapOf<String, Any?>("is_registered" to true, "bandwidth_khz" to 1400)
        val wrongService = SigmaRuleEvaluator.evaluate(
            listOf(rule), listOf(narrow), "dns_monitor", emptyMap(), emptyMap()
        )
        assertTrue("cellular rule must not fire under dns_monitor", wrongService.isEmpty())
    }
}
