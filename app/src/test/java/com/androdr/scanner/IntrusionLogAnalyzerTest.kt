package com.androdr.scanner

import com.androdr.sigma.SigmaRuleEngine
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream

class IntrusionLogAnalyzerTest {

    private val engine = mockk<SigmaRuleEngine>(relaxed = true) {
        every { evaluateDns(any()) } returns emptyList()
        every { evaluateNetwork(any()) } returns emptyList()
        every { evaluateSecurityLog(any()) } returns emptyList()
    }

    private fun entry(name: String, vararg lines: String) =
        name to ByteArrayInputStream(lines.joinToString("\n").toByteArray())

    private val day1Dns = (
        """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.a",""" +
            """"hostname":"h1.example.com","ip_addresses":["/1.1.1.1"],"ip_addresses_count":1}}"""
        )
    private val day1Net = (
        """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.a",""" +
            """"port":443,"ip_address":"/1.1.1.1"}}"""
        )
    private val day2NetDupe = day1Net // same event_id 1 — overlapping-file duplicate
    private val day2Sec = """{"security_event":{"event_id":2,"event_time":1787400350000,"tag":210002,"data":["id"]}}"""

    @Test
    fun `parses matching entries only, dedups across files, computes stats`() {
        val result = IntrusionLogAnalyzer(mockk(relaxed = true), engine).analyzeEntries(
            sequenceOf(
                entry("2026-08-21.txt", day1Dns, day1Net),
                entry("2026-08-22.txt", day2NetDupe, day2Sec),
                entry("intrusion-logs/2026-08-20.txt"),          // one dir deep: included (empty)
                entry("README.md", "not a log line"),            // non-matching: ignored entirely
            ),
            uidResolver = { -1 }, capturedAt = 42L,
        )
        assertEquals(1, result.stats.dnsEventCount)
        assertEquals(1, result.stats.connectEventCount)
        assertEquals(1, result.stats.securityEventCount)
        assertEquals(1, result.stats.duplicatesCollapsed)
        assertEquals(0, result.stats.malformedLines)
        assertEquals(1787400345334L, result.stats.earliestEventMs)
        assertEquals(1787400350000L, result.stats.latestEventMs)
    }

    @Test
    fun `evaluates all three streams through the engine`() {
        val analyzer = IntrusionLogAnalyzer(mockk(relaxed = true), engine)
        analyzer.analyzeEntries(
            sequenceOf(entry("2026-08-22.txt", day1Dns, day1Net, day2Sec)),
            uidResolver = { -1 }, capturedAt = 0L,
        )
        verify(exactly = 1) { engine.evaluateDns(match { it.size == 1 }) }
        verify(exactly = 1) { engine.evaluateNetwork(match { it.size == 1 }) }
        verify(exactly = 1) { engine.evaluateSecurityLog(match { it.size == 1 }) }
    }
}
