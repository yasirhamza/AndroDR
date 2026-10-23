package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.SignalMember
import com.androdr.data.store.StoreFixture
import com.androdr.sigma.StoreRecord
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** A signal's members load on demand, page by page, rows and facts alike (spec §5.4). */
@RunWith(RobolectricTestRunner::class)
class ClusterMembersTest {
    private val f = StoreFixture()
    private val dao get() = f.db.forensicTimelineEventDao()
    private val clusters = ClusterMembers(f.db.signalMemberDao(), dao, f.reader)

    @After fun tearDown() = f.close()

    private fun row(t: Long, scan: Long = 1L) = ForensicTimelineEvent(startTimestamp = t, source = "s",
        category = "permission_use", description = "e$t", scanResultId = scan)

    private suspend fun signal(): Long = dao.insert(ForensicTimelineEvent(startTimestamp = 1L, kind = "signal",
        source = "sigma_correlation_engine", category = "correlation", description = "chain", scanResultId = 1L))

    private suspend fun member(signal: Long, kind: Int, id: Long) =
        f.db.signalMemberDao().insertAll(listOf(SignalMember(signal, kind, id)))

    @Test
    fun `a signal with three fact members and one row member expands to four members`() = runBlocking {
        f.scan(1L, ScanState.COMPLETE)
        val facts = f.persist(1L, "appops_audit", (1..3).map {
            StoreRecord(mapOf("package_name" to "com.spy", "operation" to "android:op$it",
                "event_time_ms" to it * 1_000L))
        }).factIdByChunkIndex
        val rowId = dao.insert(row(4_000))
        val sig = signal()
        facts.forEach { member(sig, SignalMember.KIND_FACT, it) }
        member(sig, SignalMember.KIND_ROW, rowId)

        val page = clusters.load(sig, null)

        assertEquals(4, page.members.size)
        assertEquals(1, page.members.count { it is TimelineMember.RowMember })
        assertEquals(facts.toList(),
            page.members.filterIsInstance<TimelineMember.FactMember>().map { it.record.factId })
        assertEquals(0, page.missing)
        assertNull(page.next)
    }

    @Test
    fun `a signal row becomes a cluster that loads its members on expand`() {
        val sig = ForensicTimelineEvent(id = 9L, startTimestamp = 1_000L, endTimestamp = 5_000L, kind = "signal",
            source = "sigma_correlation_engine", category = "correlation", description = "Burst",
            details = """{"correlation_type":"event_count","rule_id":"r","member_count":4}""")

        val c = signalCluster(sig)

        assertEquals(9L, c.signalRowId)
        assertEquals(4, c.size)
        assertTrue("members load through ClusterMembers, not from the row", c.members.isEmpty())
        assertEquals(1_000L to 5_000L, c.startTimestamp to c.endTimestamp)
    }

    @Test
    fun `a dangling row ref is skipped and counted as missing`() = runBlocking {
        f.scan(1L, ScanState.COMPLETE)
        val live = dao.insert(row(1_000))
        val sig = signal()
        member(sig, SignalMember.KIND_ROW, live)
        member(sig, SignalMember.KIND_ROW, 999_999L)

        val page = clusters.load(sig, null)

        assertEquals(listOf(live), page.members.map { (it as TimelineMember.RowMember).row.id })
        assertEquals(1, page.missing)
    }

    @Test
    fun `a row of a scan being deleted is not shown`() = runBlocking {
        f.scan(2L, ScanState.DELETING)
        val hidden = dao.insert(row(1_000, scan = 2L))
        val sig = signal()
        member(sig, SignalMember.KIND_ROW, hidden)
        val page = clusters.load(sig, null)
        assertTrue(page.members.isEmpty())
        assertEquals(1, page.missing)
    }

    @Test
    fun `a 1,000-member signal loads in pages of 200`() = runBlocking {
        f.scan(1L, ScanState.COMPLETE)
        val ids = dao.insertAll((1..1_000).map { row(it.toLong()) })
        val sig = signal()
        f.db.signalMemberDao().insertAll(ids.map { SignalMember(sig, SignalMember.KIND_ROW, it) })

        val sizes = mutableListOf<Int>()
        val seen = mutableListOf<Long>()
        var page = clusters.load(sig, null)
        while (true) {
            sizes += page.members.size
            seen += page.members.map { (it as TimelineMember.RowMember).row.id }
            val next = page.next ?: break
            page = clusters.load(sig, next)
        }

        assertTrue("never more than 200 at once: $sizes", sizes.all { it <= ClusterMembers.PAGE })
        assertEquals(listOf(200, 200, 200, 200, 200), sizes.filter { it > 0 })
        assertEquals("every member once, in order", ids, seen)
    }
}
