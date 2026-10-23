package com.androdr.data.db

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.repo.ScanLock
import com.androdr.data.store.StoreFixture
import com.androdr.sigma.Row
import com.androdr.sigma.SignalIdentity
import com.androdr.ui.timeline.ClusterMembers
import com.androdr.ui.timeline.TimelineMember
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The one-time `signal_member` backfill (spec §5.4, gate L1): legacy signals' member lists move into
 * `signal_member`, idempotently under a kill between batches and a concurrent delete, leaving
 * malformed rows untouched and never blocking the launch.
 */
@RunWith(RobolectricTestRunner::class)
class SignalMemberBackfillTest {
    private val f = StoreFixture()
    private val dao get() = f.db.forensicTimelineEventDao()
    private val lock = ScanLock()

    @After fun tearDown() = f.close()

    /** The legacy signals' scan, COMPLETE, so their rows are visible to the reads below. */
    @org.junit.Before fun setUp() = runBlocking { f.scan(1L, ScanState.COMPLETE) }

    private fun backfill(d: SignalMemberBackfillDao = f.db.signalMemberBackfillDao()) =
        SignalMemberBackfill(f.db, d, f.db.signalMemberDao(), lock, f.dataStore)

    /** A pre-C2 signal row, its member list in `details` as the old engine wrote it. */
    private fun legacy(ids: String, details: String? = null) = ForensicTimelineEvent(
        startTimestamp = 1_000L, endTimestamp = 2_000L, kind = "signal", category = "correlation",
        source = "sigma_correlation_engine", description = "Install then admin", ruleId = "androdr-corr-001",
        details = details ?: """{"correlation_type":"temporal_ordered","rule_id":"androdr-corr-001",""" +
            """"member_event_ids":"$ids"}""",
        correlationId = "androdr-corr-001:$ids", scanResultId = 1L,
    )

    private suspend fun members(id: Long) = f.db.signalMemberDao().forSignal(id, null, null, 1_000)
    private suspend fun row(id: Long) = dao.getAllForExport().single { it.id == id }

    @Test
    fun `a legacy signal gets its members, a member_count and a canonical correlation id`() = runBlocking {
        val memberRows = dao.insertAll((1..8).map {
            ForensicTimelineEvent(startTimestamp = it.toLong(), source = "s", category = "permission_use",
                description = "e$it", scanResultId = 1L)
        })
        val (a, b, c) = listOf(memberRows[2], memberRows[4], memberRows[7])
        val id = dao.insert(legacy("$a,$b,$c"))

        val outcome = backfill().run()

        assertEquals(SignalMemberBackfill.Outcome(1, 0, completed = true), outcome)
        assertEquals(listOf(a, b, c), members(id).map { it.refId })
        val after = row(id)
        assertFalse("the list is gone from details", after.details.contains(LEGACY_KEY))
        assertTrue(after.details, after.details.contains("\"member_count\":3"))
        assertTrue("other keys kept", after.details.contains("\"correlation_type\":\"temporal_ordered\""))
        assertEquals(SignalIdentity.correlationId("androdr-corr-001", listOf(Row(a), Row(b), Row(c))),
            after.correlationId)
        val page = ClusterMembers(f.db.signalMemberDao(), dao, f.reader).load(id, null)
        assertEquals("its cluster still shows three members", 3, page.members.size)
        assertTrue(page.members.all { it is TimelineMember.RowMember })
        assertTrue(backfill().isDone())
    }

    @Test
    fun `a kill between batches then a re-run gives no duplicates`() = runBlocking {
        val ids = (1..(SignalMemberBackfill.BATCH + 5)).map { dao.insert(legacy("3,5,8")) }
        val real = f.db.signalMemberBackfillDao()
        var calls = 0
        val killed = object : SignalMemberBackfillDao by real {
            override suspend fun legacyAfter(afterId: Long, size: Int): List<LegacySignal> {
                if (++calls == 2) error("process killed")
                return real.legacyAfter(afterId, size)
            }
        }
        assertTrue(runCatching { backfill(killed).run() }.isFailure)
        assertFalse("not done after a kill", backfill().isDone())
        assertEquals("the first batch committed", SignalMemberBackfill.BATCH.toLong() * 3,
            f.count("SELECT COUNT(*) FROM signal_member"))

        val outcome = backfill().run()

        assertEquals(5, outcome.migrated)
        assertEquals("three members each, no duplicates", ids.size.toLong() * 3,
            f.count("SELECT COUNT(*) FROM signal_member"))
        assertEquals(0L, f.count("SELECT COUNT(*) FROM forensic_timeline WHERE details LIKE '%$LEGACY_KEY%'"))
    }

    @Test
    fun `a signal deleted between read and insert leaves no orphan member`() = runBlocking {
        val gone = dao.insert(legacy("3,5,8"))
        val kept = dao.insert(legacy("9"))
        val real = f.db.signalMemberBackfillDao()
        val racing = object : SignalMemberBackfillDao by real {
            override suspend fun legacyAfter(afterId: Long, size: Int): List<LegacySignal> =
                real.legacyAfter(afterId, size).also {
                    f.db.openHelper.writableDatabase.execSQL("DELETE FROM forensic_timeline WHERE id = $gone")
                }
        }

        backfill(racing).run()

        assertEquals(0L, f.count("SELECT COUNT(*) FROM signal_member WHERE signalRowId = $gone"))
        assertEquals(listOf(9L), members(kept).map { it.refId })
    }

    /** Review m-5: a member already present (a re-run after a crash mid-batch) is not duplicated. */
    @Test
    fun `a member already present is ignored, not duplicated`() = runBlocking {
        val id = dao.insert(legacy("3,5,8"))
        f.db.signalMemberDao().insertAll(listOf(com.androdr.data.model.SignalMember(id, 0, 5L)))
        backfill().run()
        assertEquals(listOf(3L, 5L, 8L), members(id).map { it.refId })
        assertTrue(row(id).details.contains("\"member_count\":3"))
    }

    @Test
    fun `non-numeric entries are dropped`() = runBlocking {
        val id = dao.insert(legacy("3,x,"))
        backfill().run()
        assertEquals(listOf(3L), members(id).map { it.refId })
        assertTrue(row(id).details.contains("\"member_count\":1"))
    }

    @Test
    fun `an unparseable row is left untouched, the launch completes and the flag is still set`() = runBlocking {
        val bad = dao.insert(legacy("", details = "not json, member_event_ids: 3,5"))
        val good = dao.insert(legacy("4"))
        val before = row(bad)

        val outcome = backfill().run()

        assertEquals(SignalMemberBackfill.Outcome(1, 1, completed = true), outcome)
        assertEquals("untouched", before, row(bad))
        assertTrue(members(bad).isEmpty())
        assertEquals(listOf(4L), members(good).map { it.refId })
        assertTrue("done after one full pass despite the failure", backfill().isDone())
        assertEquals("a done backfill does not run again", SignalMemberBackfill.Outcome(0, 0, completed = false),
            backfill().run())
    }
}
