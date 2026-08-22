package com.androdr.scanner.intrusionlog

import org.junit.Assert.assertEquals
import org.junit.Test

class IntrusionLogParserTest {

    // Real (sanitized) lines from a 2026-08-22 Samsung Android 17 export.
    private val dnsLine = (
        """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.samsun""" +
        """g.android.intellivoiceservice","hostname":"scs-apne2.bixbyllm.com","ip_addresses""" +
        """":["/34.160.125.113"],"ip_addresses_count":1}}"""
    )
    private val connectLine = (
        """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.sa""" +
        """msung.android.intellivoiceservice","port":443,"ip_address":"/34.160.125.113"}}"""
    )
    private val securityLine = (
        """{"security_event":{"event_id":2,"event_time":1787400345600,"tag":210002,"data":[""" +
        """"pm list packages"]}}"""
    )

    private fun parse(vararg lines: String) =
        IntrusionLogParser().parse(lines.asSequence(), uidResolver = { 10042 }, capturedAt = 999L)

    @Test
    fun `routes wrapper keys to the three event types`() {
        val result = parse(dnsLine, connectLine, securityLine)
        assertEquals(1, result.dnsEvents.size)
        assertEquals(1, result.networkEvents.size)
        assertEquals(1, result.securityEvents.size)
        assertEquals(0, result.malformedLines)
    }

    @Test
    fun `dns_event maps to DnsEvent with resolved ips stripped of slash prefix`() {
        val dns = parse(dnsLine).dnsEvents.single()
        assertEquals("scs-apne2.bixbyllm.com", dns.event.domain)
        assertEquals("com.samsung.android.intellivoiceservice", dns.event.appName)
        assertEquals(10042, dns.event.appUid)
        assertEquals(1787400345334L, dns.event.timestamp)
        assertEquals(false, dns.event.isBlocked)
        assertEquals(null, dns.event.reason)
        assertEquals(listOf("34.160.125.113"), dns.resolvedIps)
    }

    @Test
    fun `connect_event maps to NetworkTelemetry with null protocol`() {
        val net = parse(connectLine).networkEvents.single()
        assertEquals("34.160.125.113", net.destinationIp)
        assertEquals(443, net.destinationPort)
        assertEquals(null, net.protocol)
        assertEquals("com.samsung.android.intellivoiceservice", net.appName)
        assertEquals(999L, net.capturedAt)
    }

    @Test
    fun `security_event resolves tag name via registry`() {
        val sec = parse(securityLine).securityEvents.single()
        assertEquals(210002, sec.tag)
        assertEquals("adb_shell_cmd", sec.tagName)
        assertEquals(listOf("pm list packages"), sec.securityData)
    }

    @Test
    fun `byte-identical duplicate event_ids collapse first-seen`() {
        val result = parse(connectLine, connectLine)
        assertEquals(1, result.networkEvents.size)
        assertEquals(1, result.duplicatesCollapsed)
    }

    @Test
    fun `distinct events with same fields but different event_id are both kept`() {
        val second = connectLine.replace(""""event_id":1""", """"event_id":7""")
        val result = parse(connectLine, second)
        assertEquals(2, result.networkEvents.size)
        assertEquals(0, result.duplicatesCollapsed)
    }

    @Test
    fun `malformed lines are counted and skipped, never fatal`() {
        val result = parse("not json at all", """{"unknown_type":{"event_id":9}}""", dnsLine, "")
        assertEquals(1, result.dnsEvents.size)
        // blank lines are ignored silently; garbage + unknown wrapper count as malformed
        assertEquals(2, result.malformedLines)
    }

    @Test
    fun `uidResolver miss yields -1`() {
        val result = IntrusionLogParser().parse(
            sequenceOf(connectLine), uidResolver = { -1 }, capturedAt = 0L
        )
        assertEquals(-1, result.networkEvents.single().appUid)
    }

    @Test
    fun `security_event with non-string data values stringifies them`() {
        val line = """{"security_event":{"event_id":3,"event_time":1,"tag":210005,"data":["proc",123,true]}}"""
        val sec = parse(line).securityEvents.single()
        assertEquals(listOf("proc", "123", "true"), sec.securityData)
    }
}
