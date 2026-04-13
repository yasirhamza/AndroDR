package com.androdr.scanner.bugreport

import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WakelockParserTest {

    private val parser = WakelockParser()

    @Test
    fun `parses a single wakelock entry`() {
        val lines = """
            Power Manager State:
            Wake Locks: size=1
              PARTIAL_WAKE_LOCK                'SyncLoopWakeLock' ACQ=-2h15m30s TAG=com.example (uid=10123)

            Other State:
        """.trimIndent().lines().asSequence()

        val events = parser.parse(lines, bugreportTimestamp = 1_000_000_000L, capturedAt = 500L)

        assertEquals(1, events.size)
        val e = events.first()
        assertEquals("com.example", e.packageName)
        assertEquals("SyncLoopWakeLock", e.wakelockTag)
        assertEquals(TelemetrySource.BUGREPORT_IMPORT, e.source)
        assertEquals(500L, e.capturedAt)
        // acquiredAt = bugreportTimestamp - (2h15m30s = 8130000ms)
        assertEquals(1_000_000_000L - 8_130_000L, e.acquiredAt)
    }

    @Test
    fun `parses multiple wakelock entries`() {
        val lines = """
            Wake Locks: size=2
              PARTIAL_WAKE_LOCK 'TagA' ACQ=-10s TAG=com.foo (uid=1)
              PARTIAL_WAKE_LOCK 'TagB' ACQ=-5m TAG=com.bar (uid=2)
        """.trimIndent().lines().asSequence()

        val events = parser.parse(lines, bugreportTimestamp = 100_000L, capturedAt = 0L)
        assertEquals(2, events.size)
        assertTrue(events.any { it.packageName == "com.foo" && it.wakelockTag == "TagA" })
        assertTrue(events.any { it.packageName == "com.bar" && it.wakelockTag == "TagB" })
    }

    @Test
    fun `returns empty when no wakelock section`() {
        val lines = "unrelated bugreport text".lines().asSequence()
        assertEquals(0, parser.parse(lines, bugreportTimestamp = 0L, capturedAt = 0L).size)
    }
}
