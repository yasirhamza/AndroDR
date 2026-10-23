package com.androdr.data.store

import android.database.sqlite.SQLiteFullException
import android.os.StatFs
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TelemetryState
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.scanner.ChunkedScanWriter
import com.androdr.scanner.EvaluateOnlyDedup
import com.androdr.scanner.WriterFixture
import com.androdr.scanner.WriterFixture.Companion.APP_RULE
import com.androdr.scanner.WriterFixture.Companion.DNS_RULE
import com.androdr.scanner.WriterFixture.Companion.EVIL_APP
import com.androdr.scanner.WriterFixture.Companion.EVIL_DOMAIN
import com.androdr.scanner.WriterFixture.Companion.IMPORT_CAPTURED
import com.androdr.scanner.WriterFixture.Companion.SEC_RULE
import com.androdr.scanner.WriterFixture.Companion.securityLine
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** M1 (spec §9): preflight, the per-chunk import reserve, and the disk-full evaluate-only fallback. */
@RunWith(RobolectricTestRunner::class)
class StoragePreflightTest {
    private val w = WriterFixture()

    @After fun tearDown() = w.close()

    private val mb = 1024L * 1024
    private val il = TelemetrySource.INTRUSION_LOG_IMPORT
    private val live = TelemetrySource.LIVE_SCAN

    private fun preflight(free: Long) = StoragePreflight { mockk<StatFs> { every { availableBytes } returns free } }

    @Test
    fun `Tight when free minus estimate is below twice the estimate plus 200 MB`() {
        // 100 MB decompressed × 0.6 = 60 MB estimate; the line is free = 60 + 120 + 200 = 380 MB.
        val decompressed = 100 * mb
        val estimate = (decompressed * StoragePreflight.STORED_SIZE_FACTOR).toLong()
        val line = estimate + 2 * estimate + 200 * mb
        assertEquals(Preflight.Tight(estimate, line - 1), preflight(line - 1).check(decompressed))
        assertEquals(Preflight.Ok, preflight(line).check(decompressed))
        assertEquals(Preflight.Tight(null, 10L shl 30), preflight(10L shl 30).check(null))
        assertEquals(Preflight.Tight(null, 10L shl 30), preflight(10L shl 30).check(-1))
    }

    @Test
    fun `the reserve is a fixed 150 MB`() {
        assertEquals(150 * mb, StoragePreflight.CHUNK_RESERVE_BYTES)
        assertTrue(preflight(150 * mb).reserveOk())
        assertFalse(preflight(150 * mb - 1).reserveOk())
        assertEquals(1L, preflight(150 * mb - 1).shortfall())
    }

    @Test
    fun `import anyway - a Tight preflight does not stop the import storing`() = runBlocking {
        w.freeBytes = 300 * mb
        assertTrue(w.preflight.check(1_000 * mb) is Preflight.Tight)
        val s = w.writer.begin(w.scan(1L, il), liveEvents = false)
        s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine()))
        val r = s.finish()
        assertEquals(TelemetryState.STORED, r.telemetryState)
        assertEquals(1, r.newFacts)
    }

    @Test
    fun `headers that under-report sizes - the reserve trips and the import finishes evaluate-only`() = runBlocking {
        assertEquals(Preflight.Ok, w.preflight.check(1 * mb))
        val s = w.writer.begin(w.scan(1L, il), liveEvents = false)
        s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine(1L)))
        w.freeBytes = 100 * mb // the import was far larger than its headers said
        s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine(2L)))
        assertTrue(s.evaluateOnly)
        val r = s.finish()

        assertEquals(TelemetryState.FAILED, r.telemetryState)
        assertEquals("findings from before and after the trip", 2, r.scan.findings.count { it.ruleId == SEC_RULE })
        assertEquals(50 * mb, r.spaceToFree)
        assertEquals("only the first chunk was stored", 1L, w.count("SELECT COUNT(*) FROM scan_record"))
        assertEquals("FAILED", w.f.db.openHelper.readableDatabase
            .query("SELECT telemetryState FROM ScanResult WHERE id = 1").use { it.moveToFirst(); it.getString(0) })
    }

    @Test
    fun `the reserve is checked once more before finish`() = runBlocking {
        val s = w.writer.begin(w.scan(1L, il), liveEvents = false)
        s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine()))
        w.freeBytes = 149 * mb
        val r = s.finish()
        assertEquals(TelemetryState.FAILED, r.telemetryState)
        assertEquals(1 * mb, r.spaceToFree)
        assertEquals(1, r.scan.findings.size)
    }

    @Test
    fun `live SQLiteFullException on chunk 1 of the first service keeps findings from every service`() = runBlocking {
        val store = spyk(w.f.store)
        coEvery {
            store.persistChunk(any(), any(), any(), any(), any(), any(), any(), any(), any())
        } throws SQLiteFullException("database or disk is full")
        w.store = store
        val s = w.writer.begin(w.scan(1L), liveEvents = true)
        s.append("dns_monitor", live, CAPTURED, listOf(dns(EVIL_DOMAIN)))
        s.append("dns_monitor", live, CAPTURED, listOf(dns(EVIL_DOMAIN, time = 2L)))
        s.append("app_scanner", live, CAPTURED, listOf(app(EVIL_APP), app("com.ok")))
        val r = s.finish()

        assertTrue(r.persisted)
        assertEquals(TelemetryState.FAILED, r.telemetryState)
        assertEquals(listOf(DNS_RULE, DNS_RULE, APP_RULE), r.scan.findings.map { it.ruleId })
        assertTrue(r.scan.findings.all { it.recordId == null })
        coVerify(exactly = 1) { store.persistChunk(any(), any(), any(), any(), any(), any(), any(), any(), any()) }
        val rows = w.f.db.forensicTimelineEventDao().getAllForExport()
        assertEquals(3, rows.size)
        assertTrue(rows.all { it.recordId == null && it.level != null })
        assertEquals(0L, w.count("SELECT COUNT(*) FROM telemetry_record"))
    }

    @Test
    fun `a second failure on the findings write returns the result in memory and sets the health flag`() =
        runBlocking {
            val store = spyk(w.f.store)
            coEvery {
                store.persistChunk(any(), any(), any(), any(), any(), any(), any(), any(), any())
            } throws SQLiteFullException("full")
            val repo = spyk(w.repo)
            coEvery { repo.finish(any(), any(), any(), any()) } throws SQLiteFullException("still full")
            w.store = store
            w.repo = repo
            val s = w.writer.begin(w.scan(1L), liveEvents = true)
            s.append("app_scanner", live, CAPTURED, listOf(app(EVIL_APP)))
            val r = s.finish()

            assertFalse(r.persisted)
            assertEquals(TelemetryState.FAILED, r.telemetryState)
            assertEquals(listOf(APP_RULE), r.scan.findings.map { it.ruleId })
            assertTrue(w.health.isSet())
            assertEquals("the hidden scan is cleaned up", 0L, w.count("SELECT COUNT(*) FROM ScanResult"))
        }

    @Test
    fun `evaluate-only - two identical id-less lines yield one finding, across chunks too`() = runBlocking {
        w.freeBytes = 10 * mb // reserve breached from the first append
        val s = w.writer.begin(w.scan(1L, il), liveEvents = false)
        s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine(), securityLine()))
        s.append("security_log", il, IMPORT_CAPTURED, listOf(securityLine(), securityLine(7L)))
        val r = s.finish()
        assertEquals(TelemetryState.FAILED, r.telemetryState)
        assertEquals(2, r.scan.findings.size)
        assertEquals(0L, w.count("SELECT COUNT(*) FROM scan_record"))
    }

    @Test
    fun `evaluate-only dedup is bounded at 200000 key prefixes`() {
        assertEquals(200_000, EvaluateOnlyDedup.MAX_KEYS)
        val dedup = EvaluateOnlyDedup(capacity = 1)
        val a = securityLine(1L)
        val b = securityLine(2L)
        assertEquals(listOf(false, true), dedup.duplicates("security_log", listOf(a, a)).toList())
        // Full: b is not remembered, so its repeat is no longer caught (bounded memory over exactness).
        assertEquals(listOf(false, false, true), dedup.duplicates("security_log", listOf(b, b, a)).toList())
        // Records with no source key are never exact duplicates (distinct facts by occurrence).
        val noKey = EvaluateOnlyDedup().duplicates("dns_monitor", listOf(dns("x"), dns("x")))
        assertEquals(listOf(false, false), noKey.toList())
    }

    @Test
    fun `chunk size is 5000`() {
        assertEquals(5_000, ChunkedScanWriter.CHUNK_SIZE)
    }
}
