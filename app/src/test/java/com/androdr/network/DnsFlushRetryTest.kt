package com.androdr.network

import com.androdr.data.model.DnsEvent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
        var failNext = 0
        override suspend fun onDropped(count: Int) {
            if (failNext > 0) { failNext--; error("sink down") }
            dropped += count
        }
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
        maxSize = 100, maxBuffered = maxBuffered, flushIntervalMs = 2_000L, detached = backgroundScope,
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
    fun `flushAndStop makes one last attempt and reports what still cannot be stored as dropped`() = runTest {
        val writer = FakeWriter(failing = true) { testScheduler.currentTime }
        val health = RecordingHealth()
        val buf = buffer(writer, health).also { it.start() }
        buf.add(event(1)); buf.add(event(2))
        buf.flushAndStop()
        assertEquals(1, writer.attempts.size)
        assertEquals("nothing is left in an unowned buffer", 0, buf.pending())
        assertEquals("the unstored events are reported, not silently lost", listOf(2), health.dropped)
    }

    @Test
    fun `flushAndStop waits for a flush in progress and then offers the events added meanwhile`() = runTest {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val stored = mutableListOf<DnsEvent>()
        val buf = DnsLogBuffer(
            backgroundScope,
            flush = { batch -> gate.await(); stored += batch },
            health = RecordingHealth(), maxSize = 2, maxBuffered = 50, flushIntervalMs = 2_000L,
            detached = backgroundScope,
        )
        buf.add(event(1))
        buf.add(event(2)) // full buffer: a flush starts at once and is suspended on the gate
        runCurrent()
        buf.add(event(3)) // arrives after the in-flight snapshot
        val stopping = kotlinx.coroutines.CompletableDeferred<Unit>()
        backgroundScope.launch { buf.flushAndStop(); stopping.complete(Unit) }
        runCurrent()
        assertTrue("the stop must wait for the flush in progress", !stopping.isCompleted)
        gate.complete(Unit)
        stopping.await()
        assertEquals("every event was offered, in order", listOf(1L, 2L, 3L), stored.map { it.timestamp })
    }

    private fun TestScope.stalledBuffer(health: RecordingHealth, gate: kotlinx.coroutines.CompletableDeferred<Unit>,
                                        fails: Boolean = false, maxSize: Int = 100) =
        DnsLogBuffer(
            backgroundScope,
            flush = { gate.await(); if (fails) error("late failure") },
            health = health, maxSize = maxSize, maxBuffered = 50, flushIntervalMs = 2_000L,
            detached = backgroundScope,
        )

    @Test
    fun `shutdown with a stalled writer returns within the bound and records the dropped count`() = runTest {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val health = RecordingHealth()
        val buf = stalledBuffer(health, gate)
        (1..3).forEach { buf.add(event(it)) }
        val start = testScheduler.currentTime

        val result = kotlinx.coroutines.withTimeoutOrNull(1_500) { buf.flushAndStop() }

        assertNull("the stalled write must not complete the stop", result)
        assertEquals("the caller is released at the bound, not when the writer returns", 1_500L,
            testScheduler.currentTime - start)
        runCurrent()
        assertEquals("events not confirmed written are reported, not lost silently", listOf(3), health.dropped)
        gate.complete(Unit)
        runCurrent()
        assertEquals("a late success does not report them again", listOf(3), health.dropped)
    }

    @Test
    fun `shutdown that times out waiting behind an in-flight flush reports both batches`() = runTest {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val health = RecordingHealth()
        val buf = stalledBuffer(health, gate, maxSize = 2)
        buf.add(event(1)); buf.add(event(2)) // flush of [1, 2] starts and stalls
        runCurrent()
        buf.add(event(3)) // still buffered

        kotlinx.coroutines.withTimeoutOrNull(1_500) { buf.flushAndStop() }
        runCurrent()

        assertEquals(listOf(3), health.dropped)
        assertEquals(0, buf.pending())
    }

    @Test
    fun `an abandoned in-flight batch that later fails is neither re-queued nor reported twice`() = runTest {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val health = RecordingHealth()
        val buf = stalledBuffer(health, gate, fails = true, maxSize = 2)
        buf.add(event(1)); buf.add(event(2))
        runCurrent()
        kotlinx.coroutines.withTimeoutOrNull(1_500) { buf.flushAndStop() }
        runCurrent()
        assertEquals(listOf(2), health.dropped)

        gate.complete(Unit) // the abandoned write now fails
        runCurrent()

        assertEquals(0, buf.pending())
        assertEquals(listOf(2), health.dropped)
    }

    @Test
    fun `a drop report that fails during the outage is recorded once the database is back`() = runTest {
        val writer = FakeWriter(failing = true) { testScheduler.currentTime }
        val health = RecordingHealth().also { it.failNext = 1 }
        val buf = buffer(writer, health, maxBuffered = 10).also { it.start() }
        (1..15).forEach { buf.add(event(it)) } // 5 dropped
        advanceTimeBy(2_001); runCurrent() // flush fails; the drop report fails too
        assertTrue(health.dropped.isEmpty())
        writer.failing = false
        advanceTimeBy(2_001); runCurrent() // flush succeeds; the pending report goes through
        assertEquals(listOf(5), health.dropped)
    }

    @Test
    fun `a health callback that throws after a successful flush does not store the batch twice`() = runTest {
        val writer = FakeWriter(failing = false) { testScheduler.currentTime }
        val health = RecordingHealth().also { it.failNext = 5 }
        val buf = buffer(writer, health, maxBuffered = 2).also { it.start() }
        (1..4).forEach { buf.add(event(it)) } // 2 dropped, report pending and failing
        advanceTimeBy(2_001); runCurrent()
        advanceTimeBy(2_000); runCurrent()
        assertEquals("each event stored exactly once", listOf(3L, 4L), writer.stored.map { it.timestamp })
    }

    @Test
    fun `drops are recorded in the drop log and survive a later healthy flush`() = runTest {
        val dir = java.nio.file.Files.createTempDirectory("dnsdrop").toFile()
        val scope = CoroutineScope(kotlinx.coroutines.Dispatchers.IO + kotlinx.coroutines.SupervisorJob())
        val log = com.androdr.data.store.DnsDropLog(
            androidx.datastore.preferences.core.PreferenceDataStoreFactory.create(scope = scope) {
                java.io.File(dir, "d.preferences_pb")
            }
        )
        try {
            val writer = FakeWriter(failing = true) { testScheduler.currentTime }
            val buf = buffer(writer, DnsDropRecorder(log) { 1_000L }, maxBuffered = 10).also { it.start() }
            (1..15).forEach { buf.add(event(it)) }
            advanceTimeBy(2_001); runCurrent()
            writer.failing = false
            advanceTimeBy(60_000); runCurrent()
            // The DataStore write runs on a real thread, outside the test's virtual time.
            val state = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                var s = log.state.first()
                var tries = 0
                while (s.total == 0L && tries++ < 200) { Thread.sleep(25); s = log.state.first() }
                s
            }
            assertEquals(5L, state.total)
            assertEquals(1_000L, state.lastDropAt)
        } finally {
            scope.cancel()
        }
    }

    @Test
    fun `source gate - the drop warning is not a feed_health row`() {
        val buffer = java.io.File("src/main/java/com/androdr/network/DnsLogBuffer.kt").readText()
        val recorder = java.io.File("src/main/java/com/androdr/ioc/FeedHealthRecorder.kt").readText()
        assertTrue(!buffer.contains("FeedHealth"))
        assertTrue(!recorder.contains("dns_event_log"))
    }

    @Test
    fun `source gate - the service builds the buffer with the retrying flush`() {
        val src = java.io.File("src/main/java/com/androdr/network/DnsVpnService.kt").readText()
        assertTrue("DnsLogBuffer must not be declared in the service file again",
            !src.contains("class DnsLogBuffer"))
        assertTrue(src.contains("DnsDropRecorder("))
    }
}
