package com.androdr.ioc

import com.androdr.data.db.FeedHealthDao
import com.androdr.data.model.FeedHealth
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FeedHealthRecorderTest {

    private fun daoWithPrior(prior: FeedHealth?): Pair<FeedHealthDao, CapturingSlot> {
        val dao = mockk<FeedHealthDao>(relaxed = true)
        coEvery { dao.get(any()) } returns prior
        val slot = slot<FeedHealth>()
        coEvery { dao.upsert(capture(slot)) } returns Unit
        return dao to CapturingSlot(slot)
    }

    private class CapturingSlot(val slot: io.mockk.CapturingSlot<FeedHealth>) {
        val captured: FeedHealth get() = slot.captured
    }

    @Test
    fun `successful count clears failure streak and stamps success`() = runTest {
        val prior = FeedHealth("f", lastAttemptAt = 1, lastSuccessAt = 1, lastError = "x", consecutiveFailures = 3)
        val (dao, cap) = daoWithPrior(prior)
        val recorder = FeedHealthRecorder(dao)

        val result = recorder.recordCount("f") { 42 }

        assertEquals(42, result)
        val row = cap.captured
        assertEquals(0, row.consecutiveFailures)
        assertNull(row.lastError)
        assertTrue("lastSuccessAt should advance", row.lastSuccessAt >= prior.lastSuccessAt)
        assertEquals(row.lastAttemptAt, row.lastSuccessAt)
    }

    @Test
    fun `zero count is a failure that preserves prior success and increments streak`() = runTest {
        val prior = FeedHealth("f", lastAttemptAt = 100, lastSuccessAt = 100, lastError = null, consecutiveFailures = 2)
        val (dao, cap) = daoWithPrior(prior)
        val recorder = FeedHealthRecorder(dao)

        val result = recorder.recordCount("f") { 0 }

        assertEquals(0, result)
        val row = cap.captured
        assertEquals(3, row.consecutiveFailures)
        assertEquals("empty result", row.lastError)
        assertEquals("prior success preserved", 100L, row.lastSuccessAt)
        assertTrue("attempt advances past prior", row.lastAttemptAt >= prior.lastAttemptAt)
    }

    @Test
    fun `thrown exception is recorded as failure, not propagated, returns null`() = runTest {
        val prior = FeedHealth("f", lastAttemptAt = 5, lastSuccessAt = 5, lastError = null, consecutiveFailures = 0)
        val (dao, cap) = daoWithPrior(prior)
        val recorder = FeedHealthRecorder(dao)

        val result = recorder.record<Int>("f", succeeded = { true }) { error("boom") }

        assertNull(result)
        val row = cap.captured
        assertEquals(1, row.consecutiveFailures)
        assertEquals("boom", row.lastError)
        assertEquals("prior success preserved on exception", 5L, row.lastSuccessAt)
    }

    @Test
    fun `first-ever failure leaves lastSuccessAt at zero`() = runTest {
        val (dao, cap) = daoWithPrior(null)
        val recorder = FeedHealthRecorder(dao)

        recorder.recordCount("newfeed") { 0 }

        assertEquals(0L, cap.captured.lastSuccessAt)
        assertEquals(1, cap.captured.consecutiveFailures)
    }

    @Test
    fun `non-empty list succeeds via custom predicate`() = runTest {
        val (dao, cap) = daoWithPrior(null)
        val recorder = FeedHealthRecorder(dao)

        val result = recorder.record("f", succeeded = { it.isNotEmpty() }) { listOf(1, 2, 3) }

        assertEquals(listOf(1, 2, 3), result)
        assertEquals(0, cap.captured.consecutiveFailures)
        coVerify { dao.upsert(any()) }
    }

    @Test
    fun `successful fetch whose health upsert throws still returns the result`() = runTest {
        // A DB-write failure must NOT turn a genuine success into a discarded null.
        val dao = mockk<FeedHealthDao>(relaxed = true)
        coEvery { dao.get(any()) } returns null
        coEvery { dao.upsert(any()) } throws RuntimeException("db locked")
        val recorder = FeedHealthRecorder(dao)

        val result = recorder.recordCount("f") { 42 }

        assertEquals("success preserved despite failed health write", 42, result)
    }

    @Test
    fun `DB read failure on the failure path does not propagate`() = runTest {
        // The recorder must never abort the caller's refresh, even if the health
        // DB itself is unhealthy while recording a feed failure.
        val dao = mockk<FeedHealthDao>(relaxed = true)
        coEvery { dao.get(any()) } throws RuntimeException("db corrupt")
        coEvery { dao.upsert(any()) } returns Unit
        val recorder = FeedHealthRecorder(dao)

        val result = recorder.recordCount("f") { 0 } // empty → failure path → get() throws

        assertEquals(0, result) // returned normally, no exception escaped
    }

    @Test
    fun `every feed id has a label and isStale honors critical threshold plus streak`() {
        val ids = listOf(
            FeedHealthRecorder.FEED_INDICATORS, FeedHealthRecorder.FEED_KNOWN_APPS,
            FeedHealthRecorder.FEED_PUBLIC_REPO_IOC, FeedHealthRecorder.FEED_OEM_PREFIXES,
            FeedHealthRecorder.FEED_SIGMA_RULES, FeedHealthRecorder.FEED_CVE,
        )
        // Drift guard: a new feed id without a label would ship the raw id to users.
        ids.forEach { assertTrue("no label for $it", FeedHealthRecorder.FEED_LABELS.containsKey(it)) }

        val now = 100L * 24 * 60 * 60 * 1000
        // Fresh + no failures → not stale.
        assertTrue(!FeedHealthRecorder.isStale(FeedHealthRecorder.FEED_CVE, now, 0, now))
        // A hard-failure streak flags stale even with a recent success.
        assertTrue(FeedHealthRecorder.isStale(FeedHealthRecorder.FEED_CVE, now, 3, now))
        // Critical feed uses the tighter window: 2 days stale for critical, not for non-critical.
        val twoDaysAgo = now - 2L * 24 * 60 * 60 * 1000
        assertTrue(FeedHealthRecorder.isStale(FeedHealthRecorder.FEED_SIGMA_RULES, twoDaysAgo, 0, now))
        assertTrue(!FeedHealthRecorder.isStale(FeedHealthRecorder.FEED_INDICATORS, twoDaysAgo, 0, now))
    }
}
