package com.androdr.scanner

import android.database.sqlite.SQLiteFullException
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.scanner.WriterFixture.Companion.IMPORT_CAPTURED
import com.androdr.scanner.WriterFixture.Companion.SEC_RULE
import com.androdr.scanner.WriterFixture.Companion.securityLine
import io.mockk.coEvery
import io.mockk.coExcludeRecords
import io.mockk.excludeRecords
import io.mockk.spyk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Ruling R38 gate, under `lowHeapTest`'s 256 MB heap: an evaluate-only import of 200,000 IOC lines
 * stores every finding as a no-fact `scan_finding` row, chunk by chunk, holding none; and when the
 * no-fact writes themselves hit a full disk, the held display sample stays bounded while the counts
 * stay exact. Runs only in `lowHeapTest`; `testDebugUnitTest` excludes `*LowHeap*`.
 */
@RunWith(RobolectricTestRunner::class)
class EvaluateOnlyLowHeapTest {
    private val w = WriterFixture(recordSql = false)
    private val il = TelemetrySource.INTRUSION_LOG_IMPORT

    @After fun tearDown() = w.close()

    private fun lines() = (1L..LINES.toLong()).asSequence().map { securityLine(it) }

    @Test
    fun `an evaluate-only import of 200k IOC lines stores every finding as a no-fact row`() = runBlocking {
        assertTrue("run through the lowHeapTest task", Runtime.getRuntime().maxMemory() <= HEAP_CEILING)
        w.freeBytes = 10L shl 20 // the 150 MB reserve is breached from the first chunk
        val s = w.writer.begin(w.scan(1L, il), liveEvents = false)
        s.appendAll("security_log", il, IMPORT_CAPTURED, lines())
        val r = s.finish()

        assertEquals(TelemetryState.FAILED, r.telemetryState)
        assertEquals(LINES.toLong(), w.count("SELECT COUNT(*) FROM scan_finding WHERE recordId IS NULL"))
        assertEquals("no telemetry was stored", 0L, w.count("SELECT COUNT(*) FROM scan_record"))
        assertEquals("nothing held", 0, r.findings.size)
        assertEquals(0L, r.unsaved.count)
        assertEquals(LINES, r.scan.triggeredCount)
        assertEquals("one alert per distinct event", LINES.toLong(), w.count("SELECT COUNT(*) FROM alert"))
    }

    @Test
    fun `under a forced full disk the held sample stays bounded and the counts stay exact`() = runBlocking {
        assertTrue("run through the lowHeapTest task", Runtime.getRuntime().maxMemory() <= HEAP_CEILING)
        w.freeBytes = 10L shl 20
        val findings = spyk(w.f.findings)
        coEvery { findings.recordNoFact(any(), any(), any()) } throws SQLiteFullException("database or disk is full")
        // A spy records every call with its arguments: these hold every chunk's findings, so the
        // spy would itself break the bound this test proves.
        coExcludeRecords { findings.recordNoFact(any(), any(), any()) }
        coExcludeRecords { findings.recordStored(any(), any(), any()) }
        coExcludeRecords { findings.recordChunk(any(), any(), any(), any(), any()) }
        excludeRecords { findings.keepsRow(any()) }
        val writer = ChunkedScanWriter(w.engine, w.store, w.repo, findings, w.preflight, w.health)
        val s = writer.begin(w.scan(1L, il), liveEvents = false)
        s.appendAll("security_log", il, IMPORT_CAPTURED, lines())
        val r = s.finish()

        assertEquals("exact count", LINES.toLong(), r.unsaved.count)
        assertEquals(mapOf((SEC_RULE to "medium") to LINES.toLong()), r.unsaved.byRuleLevel)
        assertEquals("bounded sample", UnsavedFindings.UNSAVED_DISPLAY_LIMIT, r.findings.size)
        assertEquals(LINES, r.scan.triggeredCount)
        assertEquals(0L, w.count("SELECT COUNT(*) FROM scan_finding"))
    }

    private companion object {
        const val LINES = 200_000
        const val HEAP_CEILING = 280L shl 20
    }
}
