package com.androdr.scanner.bugreport

import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class TombstoneParserTest {

    private val parser = TombstoneParser()

    @Test
    fun `parses a single tombstone record with signal`() {
        val lines = """
            Build fingerprint: test
            Timestamp: 2020-02-14 09:23:45+0000
            pid: 1234, tid: 1234, name: com.example.app  >>> com.example.app <<<
            signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1234
        """.trimIndent().lines().asSequence()

        val events = parser.parse(lines, capturedAt = 5000L)

        assertEquals(1, events.size)
        val e = events.first()
        assertEquals("com.example.app", e.processName)
        assertEquals("com.example.app", e.packageName)
        assertEquals(11, e.signalNumber)
        assertNull(e.abortMessage)
        assertNotNull(e.crashTimestamp)
        assertEquals(TelemetrySource.BUGREPORT_IMPORT, e.source)
        assertEquals(5000L, e.capturedAt)
    }

    @Test
    fun `parses an abort-style tombstone without signal`() {
        val lines = """
            Timestamp: 2020-02-14 09:23:45+0000
            pid: 5678, tid: 5678, name: com.example.crash  >>> com.example.crash <<<
            Abort message: 'assertion failed'
        """.trimIndent().lines().asSequence()

        val events = parser.parse(lines, capturedAt = 1000L)

        assertEquals(1, events.size)
        val e = events.first()
        assertEquals("com.example.crash", e.processName)
        assertEquals("assertion failed", e.abortMessage)
        assertNull(e.signalNumber)
    }

    @Test
    fun `parses multiple records separated by timestamps`() {
        val lines = """
            Timestamp: 2020-02-14 09:23:45+0000
            pid: 1, tid: 1, name: com.app.one  >>> com.app.one <<<
            signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1
            Timestamp: 2020-02-14 09:25:00+0000
            pid: 2, tid: 2, name: com.app.two  >>> com.app.two <<<
            signal 6 (SIGABRT), code -6 (SI_TKILL), fault addr --------
        """.trimIndent().lines().asSequence()

        val events = parser.parse(lines, capturedAt = 0L)

        assertEquals(2, events.size)
        assertEquals("com.app.one", events[0].processName)
        assertEquals(11, events[0].signalNumber)
        assertEquals("com.app.two", events[1].processName)
        assertEquals(6, events[1].signalNumber)
    }

    @Test
    fun `returns empty list when no tombstones present`() {
        val lines = "some unrelated bugreport text\nno tombstones here".lines().asSequence()
        assertEquals(0, parser.parse(lines, capturedAt = 0L).size)
    }
}
