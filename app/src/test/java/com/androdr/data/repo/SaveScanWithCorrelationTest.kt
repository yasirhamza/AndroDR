package com.androdr.data.repo

import androidx.room.InvalidationTracker
import androidx.room.RoomDatabase
import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.IndicatorDao
import com.androdr.data.db.ScanResultDao
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Regression test for Sprint 75 fix — correlation signals were being written
 * with `member_event_ids = "0,0,0"` because the engine evaluated events before
 * Room assigned autoincrement IDs. This test drives the fix through
 * [ScanRepository.saveScanWithCorrelation] and proves that the correlator
 * lambda receives events with real (non-zero, unique) IDs.
 *
 * Uses MockK to avoid needing a real Room instance; the critical behavior
 * under test is the sequencing and ID-zipping logic in the repository, not
 * the DB itself.
 */
class SaveScanWithCorrelationTest {

    private val scanResultDao = mockk<ScanResultDao>(relaxed = true)
    private val dnsEventDao = mockk<DnsEventDao>(relaxed = true)
    private val timelineDao = mockk<ForensicTimelineEventDao>(relaxed = true)
    private val indicatorDao = mockk<IndicatorDao>(relaxed = true)
    private val database = mockk<AppDatabase>()
    private lateinit var repo: ScanRepository

    @Before
    fun setUp() {
        // Stub `database.withTransaction { block }` to just invoke the block.
        // `withTransaction` is an extension function on RoomDatabase; mockk
        // needs the generated RoomDatabaseKt class name to intercept it.
        mockkStatic("androidx.room.RoomDatabaseKt")
        val invalidationTracker = mockk<InvalidationTracker>(relaxed = true)
        every { database.invalidationTracker } returns invalidationTracker
        coEvery {
            any<RoomDatabase>().withTransaction(any<suspend () -> Any>())
        } coAnswers {
            val block = secondArg<suspend () -> Any>()
            block()
        }

        repo = ScanRepository(
            database = database,
            scanResultDao = scanResultDao,
            dnsEventDao = dnsEventDao,
            forensicTimelineEventDao = timelineDao,
            indicatorDao = indicatorDao
        )
    }

    @Test
    fun `correlator sees events with Room-assigned IDs, not zeros`() = runTest {
        val scan = ScanResult(
            id = 1L,
            timestamp = 1_700_000_000_000L,
            findings = emptyList(),
            bugReportFindings = emptyList(),
            riskySideloadCount = 0,
            knownMalwareCount = 0
        )
        val raw = listOf(
            event(cat = "permission_use", ts = 1000, pkg = "com.test"),
            event(cat = "permission_use", ts = 2000, pkg = "com.test"),
            event(cat = "permission_use", ts = 3000, pkg = "com.test")
        )
        raw.forEach { assertEquals("pre-insert default id must be 0", 0L, it.id) }

        // Simulate Room assigning autoincrement IDs 101, 102, 103.
        coEvery { timelineDao.insertAll(any()) } returns listOf(101L, 102L, 103L)

        var seenIds: List<Long> = emptyList()
        repo.saveScanWithCorrelation(
            scan = scan,
            findingTimelineEvents = raw,
            replaceUsageStatsEvents = null,
            lookbackEvents = emptyList()
        ) { eventsWithIds ->
            seenIds = eventsWithIds.map { it.id }
            emptyList()
        }

        assertEquals("correlator should see all 3 events", 3, seenIds.size)
        assertEquals(listOf(101L, 102L, 103L), seenIds)
        seenIds.forEach { assertNotEquals("id must be non-zero", 0L, it) }
    }

    @Test
    fun `signals returned by correlator are persisted after raw events`() = runTest {
        val scan = ScanResult(
            id = 2L,
            timestamp = 1_700_000_000_001L,
            findings = emptyList(),
            bugReportFindings = emptyList(),
            riskySideloadCount = 0,
            knownMalwareCount = 0
        )
        val raw = listOf(
            event(cat = "permission_use", ts = 1000, pkg = "com.test"),
            event(cat = "permission_use", ts = 2000, pkg = "com.test")
        )

        val insertedSlots = mutableListOf<List<ForensicTimelineEvent>>()
        coEvery { timelineDao.insertAll(capture(insertedSlots)) } answers {
            // Return fake IDs matching the input size for each call
            List(firstArg<List<ForensicTimelineEvent>>().size) { it.toLong() + 1 }
        }

        repo.saveScanWithCorrelation(
            scan = scan,
            findingTimelineEvents = raw,
            replaceUsageStatsEvents = null,
            lookbackEvents = emptyList()
        ) { eventsWithIds ->
            val ids = eventsWithIds.joinToString(",") { it.id.toString() }
            listOf(
                ForensicTimelineEvent(
                    startTimestamp = 1000,
                    endTimestamp = 2000,
                    kind = "signal",
                    category = "correlation",
                    source = "test",
                    description = "test cluster",
                    packageName = "com.test",
                    ruleId = "test-rule",
                    details = """{"member_event_ids":"$ids"}""",
                    scanResultId = scan.id
                )
            )
        }

        // Two insertAll calls: first for raw events, second for signals.
        assertEquals(2, insertedSlots.size)
        assertEquals("raw events first", 2, insertedSlots[0].size)
        assertEquals("signals second", 1, insertedSlots[1].size)
        val signal = insertedSlots[1].single()
        assertEquals("signal", signal.kind)
        assertTrue(
            "member_event_ids must NOT be zeros",
            !signal.details.contains("\"0,0\"")
        )
        assertTrue(
            "member_event_ids must reference the ids returned by the first insertAll",
            signal.details.contains("\"1,2\"")
        )
    }

    @Test
    fun `duplicate rows with id=-1 are filtered from correlator input`() = runTest {
        val scan = ScanResult(
            id = 3L,
            timestamp = 1_700_000_000_002L,
            findings = emptyList(),
            bugReportFindings = emptyList(),
            riskySideloadCount = 0,
            knownMalwareCount = 0
        )
        val raw = listOf(
            event(cat = "permission_use", ts = 1000, pkg = "com.a"),
            event(cat = "permission_use", ts = 2000, pkg = "com.b"),
            event(cat = "permission_use", ts = 3000, pkg = "com.c")
        )
        // Simulate Room IGNORE: middle row was a duplicate and returned id = -1.
        coEvery { timelineDao.insertAll(raw) } returns listOf(10L, -1L, 11L)

        var seenCount = 0
        var seenIds: List<Long> = emptyList()
        repo.saveScanWithCorrelation(
            scan = scan,
            findingTimelineEvents = raw,
            replaceUsageStatsEvents = null,
            lookbackEvents = emptyList()
        ) { eventsWithIds ->
            seenCount = eventsWithIds.size
            seenIds = eventsWithIds.map { it.id }
            emptyList()
        }

        assertEquals("duplicate (id = -1) row must be dropped", 2, seenCount)
        assertEquals(listOf(10L, 11L), seenIds)
    }

    // ---------- #342 B1: atomic pre-delete ----------

    /**
     * The optional `preDelete` (used by the intrusion-log replace-on-reimport
     * sweep) must run as the FIRST step INSIDE the transaction, before any
     * insert. If it ran after the inserts — or outside the transaction — a
     * failed save could not roll it back. Catches a mutation that moves the
     * `preDelete?.invoke()` below `scanResultDao.insert`.
     */
    @Test
    fun `preDelete runs first, inside the transaction, before any insert`() = runTest {
        val scan = ScanResult(
            id = 4L, timestamp = 1_700_000_000_003L, findings = emptyList(),
            bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0
        )
        val raw = listOf(event(cat = "permission_use", ts = 1000, pkg = "com.test"))
        val calls = mutableListOf<String>()
        coEvery { scanResultDao.insert(any()) } answers { calls.add("insertScan") }
        coEvery { timelineDao.insertAll(any()) } answers {
            calls.add("insertAll")
            List(firstArg<List<ForensicTimelineEvent>>().size) { it.toLong() + 1 }
        }

        repo.saveScanWithCorrelation(
            scan = scan,
            findingTimelineEvents = raw,
            replaceUsageStatsEvents = null,
            lookbackEvents = emptyList(),
            preDelete = { calls.add("preDelete") }
        ) { emptyList() }

        assertEquals("preDelete must be the very first step", "preDelete", calls.first())
        assertTrue(
            "preDelete must precede the scan insert: $calls",
            calls.indexOf("preDelete") < calls.indexOf("insertScan")
        )
        assertTrue(
            "scan insert must precede the finding insertAll: $calls",
            calls.indexOf("insertScan") < calls.indexOf("insertAll")
        )
    }

    /**
     * When an insert throws AFTER preDelete has run, the exception must
     * propagate out of `saveScanWithCorrelation`. Room's `withTransaction`
     * rethrows on failure and rolls the whole block back — INCLUDING the
     * preDelete — so a failed save can never leave the prior import destroyed
     * and the new one unwritten (#342 B1, the merge-blocking finding). Catches a
     * mutation that wraps the transaction body in a swallowing `runCatching`.
     */
    @Test
    fun `an insert failure propagates so preDelete rolls back with the transaction`() = runTest {
        val scan = ScanResult(
            id = 5L, timestamp = 1_700_000_000_004L, findings = emptyList(),
            bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0
        )
        val raw = listOf(event(cat = "permission_use", ts = 1000, pkg = "com.test"))
        var preDeleteRan = false
        coEvery { timelineDao.insertAll(any()) } throws RuntimeException("db full — insert failed")

        var thrown: Throwable? = null
        try {
            repo.saveScanWithCorrelation(
                scan = scan,
                findingTimelineEvents = raw,
                replaceUsageStatsEvents = null,
                lookbackEvents = emptyList(),
                preDelete = { preDeleteRan = true }
            ) { emptyList() }
        } catch (e: Exception) {
            thrown = e
        }

        assertTrue("preDelete must have run inside the transaction body", preDeleteRan)
        assertNotNull(
            "the persistence failure must propagate (not be swallowed) so the tx rolls back",
            thrown
        )
    }

    private fun event(cat: String, ts: Long, pkg: String) = ForensicTimelineEvent(
        startTimestamp = ts,
        kind = "event",
        category = cat,
        source = "test",
        description = "evt",
        packageName = pkg
    )
}
