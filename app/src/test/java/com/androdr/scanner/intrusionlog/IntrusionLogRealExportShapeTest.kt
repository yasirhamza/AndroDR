package com.androdr.scanner.intrusionlog

import android.app.admin.SecurityLog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Field-verification regression fixtures (#356), cut from a REAL Samsung
 * Z Fold8 / Android 16 Advanced Protection export. Package and process names are
 * sanitized; the STRUCTURE and the MAGNITUDES (nanosecond `event_time`, the
 * tag-name-as-key shape, the object-valued payload) are byte-for-byte as
 * exported.
 *
 * Two format gaps these pin:
 *  1. `security_event.event_time` is epoch NANOSECONDS (~1.79e18) while
 *     dns/connect events use epoch MILLISECONDS (~1.79e12). Un-normalized, every
 *     security event failed the sanity window and was counted malformed — the
 *     whole security stream was dropped.
 *  2. Real exports carry NO numeric `tag` and NO `data[]`. The third key (beside
 *     event_id/event_time) IS the tag name, and its value is an object of named
 *     fields. Parsed against the MVT-documented shape, every security event
 *     landed as tag -1 / "unknown_-1" with empty data — detection saw nothing.
 */
class IntrusionLogRealExportShapeTest {

    // Import wall-clock at/after the exported events (see IntrusionLogParserTest).
    private val capturedAt = 1_787_401_000_000L

    private fun parse(vararg lines: String) =
        IntrusionLogParser().parse(lines.asSequence(), uidResolver = { 10042 }, capturedAt = capturedAt)

    // ── real lines ────────────────────────────────────────────────────────────

    private val appProcessStart = (
        """{"security_event":{"event_id":0,"event_time":1787400913855464305,"app_process_start""" +
            """":{"process":"com.example.browser:sandboxed_process0","start_time":1787400913855,""" +
            """"uid":99219,"pid":23846,"seinfo":"platform:targetSdkVersion=36:complete",""" +
            """"sha256":"Failed to count APK hash"}}}"""
        )
    private val userRestrictionAdded = (
        """{"security_event":{"event_id":1,"event_time":1787400917765736231,"user_restriction_a""" +
            """dded":{"package":"NULL","admin_user":0,"restriction":"no_cellular_2g"}}}"""
        )
    private val keyguardDismissed =
        """{"security_event":{"event_id":2,"event_time":1787400917764225189,"keyguard_dismissed":{}}}"""
    private val bluetoothConnection = (
        """{"security_event":{"event_id":3,"event_time":1787400920000000000,"bluetooth_connect""" +
            """ion":{"address":"AA:BB:CC:DD:EE:FF"}}}"""
        )

    // ── item 2: nanosecond normalization ──────────────────────────────────────

    @Test
    fun `nanosecond event_time normalizes to milliseconds`() {
        val result = parse(appProcessStart)
        assertEquals("a real security_event must not be malformed", 0, result.malformedLines)
        assertEquals(1, result.securityEvents.size)
        assertEquals(1787400913855L, result.securityEvents.single().timestamp)
    }

    @Test
    fun `millisecond event_time is left untouched`() {
        val line =
            """{"dns_event":{"event_id":0,"event_time":1787400345334,"hostname":"a.example.com"}}"""
        assertEquals(1787400345334L, parse(line).dnsEvents.single().event.timestamp)
    }

    @Test
    fun `absurd future nanosecond event_time is still rejected after normalization`() {
        // 2100-01-01T00:00:00Z expressed in nanoseconds: normalizes to a real-looking
        // millisecond value that is still far beyond capturedAt + skew.
        val line = """{"security_event":{"event_id":9,"event_time":4102444800000000000,"keyguard_secured":{}}}"""
        val result = parse(line)
        assertEquals(0, result.securityEvents.size)
        assertEquals(1, result.malformedLines)
    }

    // ── item 3: real security_event shape ─────────────────────────────────────

    @Test
    fun `tag-name key resolves to the registry id and object fields become key=value data`() {
        val sec = parse(appProcessStart).securityEvents.single()
        assertEquals("app_process_start", sec.tagName)
        assertEquals(SecurityLog.TAG_APP_PROCESS_START, sec.tag)
        assertTrue(
            "process field must survive verbatim: ${sec.securityData}",
            "process=com.example.browser:sandboxed_process0" in sec.securityData
        )
        assertTrue("uid field must survive: ${sec.securityData}", "uid=99219" in sec.securityData)
        assertTrue("pid field must survive: ${sec.securityData}", "pid=23846" in sec.securityData)
        assertEquals("payload fields are rendered sorted", sec.securityData.sorted(), sec.securityData)
    }

    @Test
    fun `user_restriction_added carries its restriction value`() {
        val sec = parse(userRestrictionAdded).securityEvents.single()
        assertEquals("user_restriction_added", sec.tagName)
        assertEquals(SecurityLog.TAG_USER_RESTRICTION_ADDED, sec.tag)
        assertTrue("restriction=no_cellular_2g" in sec.securityData)
    }

    @Test
    fun `empty payload object parses with empty security data, never malformed`() {
        val result = parse(keyguardDismissed)
        assertEquals(0, result.malformedLines)
        val sec = result.securityEvents.single()
        assertEquals("keyguard_dismissed", sec.tagName)
        assertEquals(SecurityLog.TAG_KEYGUARD_DISMISSED, sec.tag)
        assertTrue("an empty object yields no data entries", sec.securityData.isEmpty())
    }

    @Test
    fun `unknown tag name is emitted with tag -1 rather than dropped`() {
        val line =
            """{"security_event":{"event_id":4,"event_time":1787400920000000000,"future_event":{"k":"v"}}}"""
        val result = parse(line)
        assertEquals("an unrecognized tag name is a fact, not a parse failure", 0, result.malformedLines)
        val sec = result.securityEvents.single()
        assertEquals("future_event", sec.tagName)
        assertEquals(-1, sec.tag)
        assertEquals(listOf("k=v"), sec.securityData)
    }

    @Test
    fun `a security_event with no payload key at all is emitted, not dropped`() {
        val line = """{"security_event":{"event_id":5,"event_time":1787400920000000000}}"""
        val result = parse(line)
        assertEquals(0, result.malformedLines)
        val sec = result.securityEvents.single()
        assertEquals("unknown_-1", sec.tagName)
        assertEquals(-1, sec.tag)
        assertTrue(sec.securityData.isEmpty())
    }

    @Test
    fun `non-object payload value is stringified into a single data element`() {
        val line =
            """{"security_event":{"event_id":6,"event_time":1787400920000000000,"logging_started":"yes"}}"""
        val sec = parse(line).securityEvents.single()
        assertEquals("logging_started", sec.tagName)
        assertEquals(listOf("yes"), sec.securityData)
    }

    @Test
    fun `the MVT-documented numeric tag plus data array shape still parses`() {
        // Other OEMs may emit the documented shape; the fallback must survive.
        val line =
            """{"security_event":{"event_id":7,"event_time":1787400345600,"tag":210002,"data":["pm list packages"]}}"""
        val sec = parse(line).securityEvents.single()
        assertEquals(210002, sec.tag)
        assertEquals("adb_shell_cmd", sec.tagName)
        assertEquals(listOf("pm list packages"), sec.securityData)
    }

    @Test
    fun `control characters inside a real-shape payload value are neutralized`() {
        val line =
            """{"security_event":{"event_id":8,"event_time":1787400920000000000,"package_updated":""" +
                """{"package":"com.a\n------\n FINDINGS"}}}"""
        val data = parse(line).securityEvents.single().securityData.single()
        assertTrue("a payload value must not forge a report section: $data", !data.contains('\n'))
    }

    // ── whole-file guard ──────────────────────────────────────────────────────

    @Test
    fun `a real-shape export chunk parses with zero malformed lines`() {
        val fixture = listOf(
            """{"dns_event":{"event_id":0,"event_time":1787400345334,"package_name":"com.example.assistant",""" +
                """"hostname":"scs.example-llm.com","ip_addresses":["/34.160.125.113"],"ip_addresses_count":1}}""",
            """{"connect_event":{"event_id":1,"event_time":1787400345540,"package_name":"com.example.assistant",""" +
                """"port":443,"ip_address":"/34.160.125.113"}}""",
            appProcessStart,
            userRestrictionAdded,
            keyguardDismissed,
            bluetoothConnection,
            """{"security_event":{"event_id":4,"event_time":1787400921000000000,"key_generated":""" +
                """{"success":1,"key_id":"example_key","uid":10042}}}""",
            """{"security_event":{"event_id":5,"event_time":1787400922000000000,"key_destruction":""" +
                """{"success":1,"key_id":"example_key","uid":10042}}}""",
            """{"security_event":{"event_id":6,"event_time":1787400923000000000,"logging_started":{}}}""",
            """{"security_event":{"event_id":7,"event_time":1787400924000000000,"package_updated":""" +
                """{"package":"com.example.browser","version":142,"uid":99219}}}"""
        )
        val result = IntrusionLogParser().parse(
            fixture.asSequence(), uidResolver = { -1 }, capturedAt = capturedAt
        )
        assertEquals("a real export chunk must parse clean", 0, result.malformedLines)
        assertEquals(1, result.dnsEvents.size)
        assertEquals(1, result.networkEvents.size)
        assertEquals(8, result.securityEvents.size)
        assertTrue(
            "every security event must resolve a real tag name",
            result.securityEvents.none { it.tagName.startsWith("unknown_") }
        )
    }
}
