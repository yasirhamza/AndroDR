package com.androdr.data.db

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowLog

/**
 * Final review M6: a stored finding that no longer decodes logged the exception's message, and a
 * kotlinx `SerializationException` message quotes the JSON input ("JSON input: ..."), which can hold
 * package names or domains. The app log is copied into exported reports, so the log line carries the
 * row's ids and the exception's class only.
 */
@RunWith(RobolectricTestRunner::class)
class FindingDecodeLogTest {

    @Before fun clearLogs() = ShadowLog.reset()

    @Test
    fun `a decode failure logs the row ids and the exception class, never the record content`() {
        val corrupt = """{"ruleId":"androdr-001","matchContext":{"package_name":"com.secret.victim"},"level":7"""
        assertNull(Converters.decodeFinding(corrupt, "scan_finding 7 of scan 3"))
        val line = ShadowLog.getLogsForTag("Converters").single().msg
        assertTrue(line, line.contains("scan_finding 7 of scan 3"))
        assertTrue(line, line.contains("Exception"))
        assertFalse("no record content: $line", line.contains("com.secret.victim"))
        assertFalse("no JSON excerpt: $line", line.contains("JSON input", ignoreCase = true))
    }

    @Test
    fun `the legacy findings list and scanner errors decode failures log no content either`() {
        assertEquals(emptyList<Any>(), Converters.toFindingList("""[{"package_name":"com.secret.list"""))
        assertEquals(emptyList<Any>(), Converters.toScannerFailureList("""[{"message":"com.secret.err"""))
        val lines = ShadowLog.getLogsForTag("Converters").map { it.msg }
        assertEquals(2, lines.size)
        lines.forEach { assertFalse(it, it.contains("com.secret") || it.contains("JSON input", ignoreCase = true)) }
    }
}
