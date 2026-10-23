package com.androdr.network

import com.androdr.data.db.FeedHealthDao
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FeedHealth
import com.androdr.ioc.FeedHealthRecorder
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A7c: the DNS event buffer must not lose events on one failed flush, must back off between
 * retries, and must stay bounded (dropping the oldest, with a health warning) when the database
 * stays unavailable.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DnsFlushRetryTest {

    private fun event(i: Int) = DnsEvent(
        id = 0, timestamp = i.toLong(), domain = "d$i.example", appUid = -1, appName = null,
        isBlocked = false, reason = null,
    )

    private class RecordingHealth : DnsBufferHealth {
        val dropped = mutableListOf<Int>()
        var recovered = 0
        override suspend fun onDropped(count: Int) { dropped += count }
        override suspend fun onRecovered() { recovered++ }
    }

    private class FakeWriter(var failing: Boolean, val now: () -> Long) {
        val attempts = mutableListOf<Long>()
        val stored = mutableListOf<DnsEvent>()
        suspend fun write(batch: List<DnsEvent>) {
            attempts += now()
            if (failing) error("database is locked")
            stored += batch
        }
    }

    private fun TestScope.buffer(
        writer: FakeWriter,
        health: DnsBufferHealth,
        maxBuffered: Int = 50,
        scope: CoroutineScope = backgroundScope,
    ) = DnsLogBuffer(
        scope, flush = writer::write, health = health,
        maxSize = 100, maxBuffered = maxBuffered, flushIntervalMs = 2_000L,
    )

    @Test
    fun `a failed flush is retried with doubling backoff and nothing is lost`() = runTest {
        val writer = FakeWriter(failing = true) { testScheduler.currentTime }
        val health = RecordingHealth()
        val buf = buffer(writer, health).also { it.start() }
        (1..3).forEach { buf.add(event(it)) }

        // interval 2 s, then waits of 2 s, 4 s, 8 s after the first three failures
        advanceTimeBy(2_000 + 2_000 + 4_000 + 8_000 + 1)
        runCurrent()
        assertEquals(listOf(2_000L, 4_000L, 8_000L, 16_000L), writer.attempts)

        writer.failing = false
        advanceTimeBy(16_000 + 1)
        runCurrent()
        assertEquals("all three events stored once, in order", listOf(1L, 2L, 3L), writer.stored.map { it.timestamp })
        assertEquals(0, buf.pending())
        assertEquals("recovery is reported once", 1, health.recovered)
        assertTrue("no events dropped", health.dropped.isEmpty())
    }

    @Test
    fun `backoff doubles and is capped, and a success resets it`() {
        assertEquals(2_000L, DnsLogBuffer.backoffMs(1))
        assertEquals(4_000L, DnsLogBuffer.backoffMs(2))
        assertEquals(8_000L, DnsLogBuffer.backoffMs(3))
        assertEquals(DnsLogBuffer.MAX_BACKOFF_MS, DnsLogBuffer.backoffMs(40))
    }

    @Test
    fun `after recovery the next flush uses the plain interval again`() = runTest {
        val writer = FakeWriter(failing = true) { testScheduler.currentTime }
        val buf = buffer(writer, RecordingHealth()).also { it.start() }
        buf.add(event(1))
        advanceTimeBy(2_001); runCurrent() // fails at 2 s
        writer.failing = false
        advanceTimeBy(2_000); runCurrent() // retried at 4 s, succeeds
        assertEquals(listOf(2_000L, 4_000L), writer.attempts)
        buf.add(event(2))
        advanceTimeBy(2_000); runCurrent()
        assertEquals("interval, not backoff, after a success", listOf(2_000L, 4_000L, 6_000L), writer.attempts)
    }

    @Test
    fun `while flushes fail the buffer stays bounded and the oldest events are dropped with a warning`() = runTest {
        val writer = FakeWriter(failing = true) { testScheduler.currentTime }
        val health = RecordingHealth()
        val buf = buffer(writer, health, maxBuffered = 50).also { it.start() }

        (1..200).forEach { buf.add(event(it)) }
        assertTrue("never above the bound: ${buf.pending()}", buf.pending() <= 50)
        advanceTimeBy(2_001); runCurrent() // a failed flush re-queues, then trims
        assertTrue(buf.pending() <= 50)

        writer.failing = false
        advanceTimeBy(2_000); runCurrent()
        assertEquals("the newest 50 survive", (151L..200L).toList(), writer.stored.map { it.timestamp })
        assertEquals("the 150 dropped events are reported", 150, health.dropped.sum())
    }

    @Test
    fun `a failed flush with a full backlog trims the re-queued batch and warns`() = runTest {
        val writer = FakeWriter(failing = true) { testScheduler.currentTime }
        val health = RecordingHealth()
        val buf = buffer(writer, health, maxBuffered = 10).also { it.start() }
        (1..10).forEach { buf.add(event(it)) }
        advanceTimeBy(2_001); runCurrent() // flush fails, batch of 10 re-queued
        (11..15).forEach { buf.add(event(it)) } // pushes past the bound while in backoff
        assertEquals(10, buf.pending())
        writer.failing = false
        advanceTimeBy(2_001); runCurrent()
        assertEquals((6L..15L).toList(), writer.stored.map { it.timestamp })
        assertEquals(5, health.dropped.sum())
    }

    @Test
    fun `a full buffer does not hammer a failing database`() = runTest {
        val writer = FakeWriter(failing = true) { testScheduler.currentTime }
        val buf = buffer(writer, RecordingHealth(), maxBuffered = 1_000).also { it.start() }
        (1..100).forEach { buf.add(event(it)) } // reaches maxSize: one immediate flush, fails
        runCurrent()
        val afterFirst = writer.attempts.size
        (101..400).forEach { buf.add(event(it)) } // still above maxSize, but in backoff
        runCurrent()
        assertEquals("no immediate flush while failing", afterFirst, writer.attempts.size)
    }

    @Test
    fun `flushAndStop makes one last attempt and keeps the events when it fails`() = runTest {
        val writer = FakeWriter(failing = true) { testScheduler.currentTime }
        val buf = buffer(writer, RecordingHealth()).also { it.start() }
        buf.add(event(1))
        buf.flushAndStop()
        assertEquals(1, writer.attempts.size)
        assertEquals(1, buf.pending())
    }

    @Test
    fun `health recorder writes a failing dns_event_log row and clears it on recovery`() = runTest {
        val rows = mutableMapOf<String, FeedHealth>()
        val dao = mockk<FeedHealthDao>()
        coEvery { dao.get(any()) } answers { rows[firstArg()] }
        coEvery { dao.upsert(any()) } answers { rows[firstArg<FeedHealth>().feedId] = firstArg() }
        val recorder = DnsBufferHealthRecorder(dao) { 1_000L }

        recorder.onDropped(7)
        recorder.onDropped(3)
        val row = rows.getValue(FeedHealthRecorder.FEED_DNS_EVENT_LOG)
        assertEquals(2, row.consecutiveFailures)
        assertTrue(row.lastError!!.contains("dropped 3"))

        recorder.onRecovered()
        val healed = rows.getValue(FeedHealthRecorder.FEED_DNS_EVENT_LOG)
        assertEquals(0, healed.consecutiveFailures)
        assertEquals(null, healed.lastError)
        coVerify(exactly = 3) { dao.upsert(any()) }
    }

    @Test
    fun `health recorder never throws when the database is the problem`() = runTest {
        val dao = mockk<FeedHealthDao>()
        coEvery { dao.get(any()) } throws IllegalStateException("db closed")
        DnsBufferHealthRecorder(dao).onDropped(1)
        DnsBufferHealthRecorder(dao).onRecovered()
    }

    @Test
    fun `source gate - the service builds the buffer with the retrying flush`() {
        val src = java.io.File("src/main/java/com/androdr/network/DnsVpnService.kt").readText()
        assertTrue("DnsLogBuffer must not be declared in the service file again",
            !src.contains("class DnsLogBuffer"))
        assertTrue(src.contains("DnsBufferHealthRecorder("))
    }
}
