package com.androdr.scanner.intrusionlog

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
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

    // A capturedAt at/after the imported events: import always happens after the
    // events occur, and (since #342 event_time validation) event_time must be
    // <= capturedAt + skew, so the prior arbitrary small values (0L / 999L) would
    // now reject every real 2026 timestamp as malformed.
    private val capturedAt = 1_787_400_400_000L

    private fun parse(vararg lines: String) =
        IntrusionLogParser().parse(lines.asSequence(), uidResolver = { 10042 }, capturedAt = capturedAt)

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
        assertEquals(capturedAt, net.capturedAt)
    }

    @Test
    fun `security_event resolves tag name via registry`() {
        val sec = parse(securityLine).securityEvents.single()
        assertEquals(210002, sec.tag)
        assertEquals("adb_shell_cmd", sec.tagName)
        assertEquals(listOf("pm list packages"), sec.securityData)
    }

    @Test
    fun `byte-identical duplicate collapse first-seen`() {
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

    // Finding 1: dedup on (event_id, event_time, wrapper_type). event_id may be a
    // per-day counter that restarts at 0, so two records sharing an id but with
    // different event_time are DISTINCT and must both survive — the old
    // event_id-only key silently dropped one, importing only day 1 of an export.
    @Test
    fun `same event_id with different event_time are both kept (per-day restart)`() {
        val a = """{"dns_event":{"event_id":0,"event_time":1787400345334,"hostname":"a.example.com"}}"""
        val b = """{"dns_event":{"event_id":0,"event_time":1787400399999,"hostname":"b.example.com"}}"""
        val result = parse(a, b)
        assertEquals(2, result.dnsEvents.size)
        assertEquals(0, result.duplicatesCollapsed)
    }

    @Test
    fun `byte-identical record sharing all three key fields collapses`() {
        val a = """{"dns_event":{"event_id":0,"event_time":1787400345334,"hostname":"a.example.com"}}"""
        val result = parse(a, a)
        assertEquals(1, result.dnsEvents.size)
        assertEquals(1, result.duplicatesCollapsed)
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
            sequenceOf(connectLine), uidResolver = { -1 }, capturedAt = capturedAt
        )
        assertEquals(-1, result.networkEvents.single().appUid)
    }

    @Test
    fun `security_event with non-string data values stringifies them`() {
        val line =
            """{"security_event":{"event_id":3,"event_time":1787400345600,"tag":210005,""" +
                """"data":["proc",123,true]}}"""
        val sec = parse(line).securityEvents.single()
        assertEquals(listOf("proc", "123", "true"), sec.securityData)
    }

    // Finding 2: security_event records have never been sampled; if they lack an
    // event_id, the old `!!` dropped EVERY security event and the service shipped
    // dead. A missing id must synthesize a dedup identity, not drop the record.
    @Test
    fun `security_event without event_id is parsed, not malformed`() {
        val line = """{"security_event":{"event_time":1787400345600,"tag":210002,"data":["id"]}}"""
        val result = parse(line)
        assertEquals(1, result.securityEvents.size)
        assertEquals(0, result.malformedLines)
    }

    // Finding 2: a nested array/object inside data[] must be stringified, not
    // thrown (which the old jsonPrimitive access did, dropping the whole record).
    @Test
    fun `security_event data with nested array or object is stringified, not dropped`() {
        val line =
            """{"security_event":{"event_id":5,"event_time":1787400345600,"tag":210005,""" +
                """"data":["proc",[1,2],{"k":"v"}]}}"""
        val result = parse(line)
        assertEquals(0, result.malformedLines)
        val data = result.securityEvents.single().securityData
        assertEquals("proc", data[0])
        assertEquals("[1,2]", data[1])
        assertEquals("""{"k":"v"}""", data[2])
    }

    // Finding 5: an out-of-window event_time (Long.MAX pins fabricated rows atop
    // the timeline forever) is rejected as malformed rather than ingested.
    @Test
    fun `absurd future event_time is rejected as malformed`() {
        val line =
            """{"dns_event":{"event_id":0,"event_time":9223372036854775807,"hostname":"a.example.com"}}"""
        val result = parse(line)
        assertEquals(0, result.dnsEvents.size)
        assertEquals(1, result.malformedLines)
    }

    @Test
    fun `pre-2008 event_time is rejected as malformed`() {
        val line = """{"dns_event":{"event_id":0,"event_time":1000,"hostname":"a.example.com"}}"""
        val result = parse(line)
        assertEquals(0, result.dnsEvents.size)
        assertEquals(1, result.malformedLines)
    }

    // Finding 3a: an over-long line is counted malformed and never parsed.
    @Test
    fun `over-long line is counted malformed and not parsed`() {
        val parser = IntrusionLogParser(maxLineLength = 100)
        val longHost = "a".repeat(500)
        val line =
            """{"dns_event":{"event_id":0,"event_time":1787400345334,"hostname":"$longHost"}}"""
        val result = parser.parse(sequenceOf(line), uidResolver = { -1 }, capturedAt = capturedAt)
        assertEquals(0, result.dnsEvents.size)
        assertEquals(1, result.malformedLines)
    }

    // Finding 3b: exceeding a per-type record cap drops extras and sets truncated.
    @Test
    fun `exceeding a per-type record cap sets truncated and drops extras`() {
        val parser = IntrusionLogParser(maxDnsRecords = 2)
        val lines = (0..4).map { i ->
            """{"dns_event":{"event_id":$i,"event_time":${1787400345334L + i},"hostname":"h$i.example.com"}}"""
        }
        val result = parser.parse(lines.asSequence(), uidResolver = { -1 }, capturedAt = capturedAt)
        assertEquals(2, result.dnsEvents.size)
        assertTrue(result.truncated)
    }

    @Test
    fun `a clean parse reports truncated false`() {
        assertFalse(parse(dnsLine, connectLine, securityLine).truncated)
    }

    // Finding 6: CR/LF and control chars in ingested string fields are neutralized
    // so a crafted hostname/ip/package cannot forge a newline-delimited report
    // section. In the raw Kotlin string, `\n` is a JSON escape that decodes to a
    // real newline inside the parsed value.
    @Test
    fun `control characters in dns string fields are neutralized before emission`() {
        val line =
            """{"dns_event":{"event_id":0,"event_time":1787400345334,""" +
                """"package_name":"com.a\ncom.b","hostname":"evil.com\n------\n FINDINGS",""" +
                """"ip_addresses":["/1.2.3.4\nX"]}}"""
        val dns = parse(line).dnsEvents.single()
        assertFalse(dns.event.domain.contains('\n'))
        assertFalse(dns.event.appName!!.contains('\n'))
        assertFalse(dns.resolvedIps.single().contains('\n'))
    }

    @Test
    fun `control characters in connect ip and package are neutralized`() {
        val line =
            """{"connect_event":{"event_id":0,"event_time":1787400345540,""" +
                """"package_name":"com.a\n----","port":443,"ip_address":"/9.9.9.9\n----"}}"""
        val net = parse(line).networkEvents.single()
        assertFalse(net.destinationIp.contains('\n'))
        assertFalse(net.appName!!.contains('\n'))
    }

    @Test
    fun `control characters in security data are neutralized`() {
        val line =
            """{"security_event":{"event_id":0,"event_time":1787400345334,"tag":210002,""" +
                """"data":["ok\n------\n FINDINGS"]}}"""
        val data = parse(line).securityEvents.single().securityData.single()
        assertFalse(data.contains('\n'))
    }

    // Minor (batch A review): hostname is a dns_event's DEFINING payload — an
    // absent/blank one must be malformed, not an empty-domain phantom row that
    // inflates dnsEventCount and implies a DNS lookup was observed.
    @Test
    fun `dns_event without hostname is malformed and emits no phantom row`() {
        val line = """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.a"}}"""
        val result = parse(line)
        assertEquals(0, result.dnsEvents.size)
        assertEquals(1, result.malformedLines)
    }

    @Test
    fun `dns_event with control-char-only hostname collapses to blank and is malformed`() {
        // hostname sanitizes to a single space -> blank -> malformed (sanitize
        // runs before the blank check).
        val line = """{"dns_event":{"event_id":0,"event_time":1787400345334,"hostname":"\n"}}"""
        val result = parse(line)
        assertEquals(0, result.dnsEvents.size)
        assertEquals(1, result.malformedLines)
    }

    // Minor: ip_address + port are a connect_event's DEFINING payload.
    @Test
    fun `connect_event without ip_address is malformed and emits no phantom row`() {
        val line = """{"connect_event":{"event_id":1,"event_time":1787400345540,"port":443}}"""
        val result = parse(line)
        assertEquals(0, result.networkEvents.size)
        assertEquals(1, result.malformedLines)
    }

    @Test
    fun `connect_event without port is malformed`() {
        val line =
            """{"connect_event":{"event_id":1,"event_time":1787400345540,"ip_address":"/1.2.3.4"}}"""
        val result = parse(line)
        assertEquals(0, result.networkEvents.size)
        assertEquals(1, result.malformedLines)
    }

    // Re-confirm the robustness that MUST stay: a secondary field (package_name)
    // absent still parses, with the defining payload (hostname) intact.
    @Test
    fun `dns_event missing only package_name still parses with domain intact`() {
        val line =
            """{"dns_event":{"event_id":0,"event_time":1787400345334,"hostname":"only.example.com"}}"""
        val dns = parse(line).dnsEvents.single()
        assertEquals("only.example.com", dns.event.domain)
        assertEquals(null, dns.event.appName)
        assertEquals(-1, dns.event.appUid)
    }

    // Finding 4: the onLine check (the analyzer threads coroutineContext
    // .ensureActive() into it) runs before the per-line try/catch, so throwing
    // from it stops the loop instead of being swallowed as a malformed line.
    @Test
    fun `onLine cancellation check runs before processing and halts the loop`() {
        var calls = 0
        val lines = (0..9).map { i ->
            """{"dns_event":{"event_id":$i,"event_time":${1787400345334L + i},"hostname":"h$i.com"}}"""
        }
        try {
            IntrusionLogParser().parse(
                lines.asSequence(), uidResolver = { -1 }, capturedAt = capturedAt,
                onLine = {
                    calls++
                    if (calls >= 3) throw kotlin.coroutines.cancellation.CancellationException("cancelled")
                }
            )
            fail("expected CancellationException to propagate out of parse()")
        } catch (_: kotlin.coroutines.cancellation.CancellationException) {
            // expected — the check was NOT swallowed by the per-line catch
        }
        // Stopped at the 3rd check rather than running all 10 lines.
        assertEquals(3, calls)
    }
}
