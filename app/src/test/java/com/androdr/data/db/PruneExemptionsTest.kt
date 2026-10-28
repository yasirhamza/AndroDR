package com.androdr.data.db

import androidx.room.withTransaction
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.SignalMember
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.TimelineRowDeleter
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.StoreFixture.Companion.app
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * P1 and P2 (spec §5.6, §9): the 30-day prune removes only non-persistent `LIVE_SCAN` rows that no
 * `signal_member` row ref of a surviving signal points at, whatever their `scanResultId`. A pruned
 * signal takes its members with it, and every fact pin the prune removes (row `recordId`s and the
 * pruned members' fact refs) is released in the same transaction (A5).
 */
@RunWith(RobolectricTestRunner::class)
class PruneExemptionsTest {
    private val f = StoreFixture()
    private val dao = f.db.forensicTimelineEventDao()
    private val deleter = TimelineRowDeleter(dao, f.store, f.db.signalMemberDao())

    @After fun tearDown() = f.close()

    private companion object {
        const val DAY = 24L * 60 * 60 * 1000
        const val NOW = 400L * DAY
        const val OLD = NOW - 31 * DAY
        const val CUTOFF = NOW - 30 * DAY
    }

    @Suppress("LongParameterList")
    private fun row(
        desc: String, createdAt: Long = OLD, scan: Long = -1L, kind: String = "event",
        source: TelemetrySource = TelemetrySource.LIVE_SCAN, persistent: Boolean = false, category: String = "c",
    ) = ForensicTimelineEvent(startTimestamp = 1L, source = "s", category = category, description = desc,
        scanResultId = scan, kind = kind, telemetrySource = source, createdAt = createdAt, persistent = persistent)

    private fun descriptions(): List<String> = f.db.openHelper.readableDatabase
        .query("SELECT description FROM forensic_timeline ORDER BY description")
        .use { c -> buildList { while (c.moveToNext()) add(c.getString(0)) } }

    private suspend fun prune() = f.db.withTransaction { deleter.olderThan(CUTOFF) }

    private fun orphanMembers() = f.count("SELECT COUNT(*) FROM signal_member m WHERE NOT EXISTS " +
        "(SELECT 1 FROM forensic_timeline s WHERE s.id = m.signalRowId)")

    @Test
    fun `P1 import rows, persistent rows and rows a surviving signal references survive the prune`() =
        runBlocking {
            dao.insert(row("intrusion import", source = TelemetrySource.INTRUSION_LOG_IMPORT))
            dao.insert(row("bugreport import", source = TelemetrySource.BUGREPORT_IMPORT, scan = 9L))
            dao.insert(row("closure", persistent = true, category = "alert_closed"))
            dao.insert(row("audit", persistent = true, category = "scan_deleted"))
            dao.insert(row("import interrupted", persistent = true, category = "import_interrupted"))
            val member = dao.insert(row("member of a live signal"))
            val survivor = dao.insert(row("fresh signal", createdAt = NOW, kind = "signal"))
            f.db.signalMemberDao().insertAll(listOf(SignalMember(survivor, SignalMember.KIND_ROW, member)))
            dao.insert(row("stale"))

            prune()

            assertEquals(listOf("audit", "bugreport import", "closure", "fresh signal", "import interrupted",
                "intrusion import", "member of a live signal"), descriptions())
            assertEquals(1L, f.count("SELECT COUNT(*) FROM signal_member"))
        }

    @Test
    fun `P2 a 31-day-old live ioc_match row with no owning scan is pruned, a persistent one is not`() =
        runBlocking {
            dao.insert(row("live ioc match", category = "ioc_match"))
            dao.insert(row("live ioc match of a kept scan", category = "ioc_match", scan = 5L))
            dao.insert(row("persistent ioc audit", category = "ioc_match", persistent = true))
            dao.insert(row("fresh ioc match", category = "ioc_match", createdAt = NOW))
            prune()
            assertEquals(listOf("fresh ioc match", "persistent ioc audit"), descriptions())
        }

    @Test
    fun `a pruned signal takes its members, and their pins and the rows' pins are released`() = runBlocking {
        f.scan(1L, ScanState.COMPLETE)
        val facts = f.persist(1L, "app_scanner", listOf(app("com.member"), app("com.row"), app("com.kept")))
            .factIdByChunkIndex
        val memberFact = facts[0]
        val rowFact = facts[1]
        val keptFact = facts[2]
        val memberRow = dao.insert(row("old member row").copy(recordId = rowFact))
        val sig = dao.insert(row("old signal", kind = "signal"))
        f.db.signalMemberDao().insertAll(listOf(SignalMember(sig, SignalMember.KIND_FACT, memberFact),
            SignalMember(sig, SignalMember.KIND_ROW, memberRow)))
        dao.insert(row("import row pins", source = TelemetrySource.INTRUSION_LOG_IMPORT).copy(recordId = keptFact))
        f.store.deleteScanTelemetry(1L)
        f.db.scanResultDao().deleteById(1L)
        assertEquals("every fact is pinned", 3L, f.count("SELECT COUNT(*) FROM telemetry_record"))

        prune()

        assertEquals("the signal and the row it alone referenced go", listOf("import row pins"), descriptions())
        assertEquals(0L, f.count("SELECT COUNT(*) FROM signal_member"))
        assertEquals("the member's and the row's pins are released; the import row's pin stays",
            listOf(keptFact), f.db.openHelper.readableDatabase.query("SELECT id FROM telemetry_record")
                .use { c -> buildList { while (c.moveToNext()) add(c.getLong(0)) } })
        assertEquals("no unreferenced body is left", 0L, f.count("SELECT COUNT(*) FROM record_body b WHERE " +
            "NOT EXISTS (SELECT 1 FROM telemetry_record t WHERE t.bodyHash = b.hash)"))
    }

    @Test
    fun `a signal's ref to itself does not exempt it from the prune`() = runBlocking {
        val sig = dao.insert(row("old self-listing signal", kind = "signal"))
        f.db.signalMemberDao().insertAll(listOf(SignalMember(sig, SignalMember.KIND_ROW, sig)))
        prune()
        assertEquals(emptyList<String>(), descriptions())
        assertEquals(0L, f.count("SELECT COUNT(*) FROM signal_member"))
    }

    /**
     * An old signal that is itself a member of a fresh signal survives with its members; an old signal
     * referenced only by a pruned signal waits for the next prune, so no member is ever left orphaned.
     */
    @Test
    fun `the prune never leaves a member whose signal row is gone`() = runBlocking {
        val inner = dao.insert(row("old inner signal", kind = "signal"))
        val outer = dao.insert(row("old outer signal", kind = "signal"))
        val kept = dao.insert(row("old kept signal", kind = "signal"))
        val fresh = dao.insert(row("fresh signal", createdAt = NOW, kind = "signal"))
        val leaf = dao.insert(row("old leaf"))
        f.db.signalMemberDao().insertAll(listOf(
            SignalMember(outer, SignalMember.KIND_ROW, inner),
            SignalMember(inner, SignalMember.KIND_ROW, leaf),
            SignalMember(fresh, SignalMember.KIND_ROW, kept),
            SignalMember(kept, SignalMember.KIND_ROW, 4242L),
        ))

        prune()

        assertEquals(0L, orphanMembers())
        assertEquals(listOf("fresh signal", "old inner signal", "old kept signal", "old leaf"), descriptions())
        prune()
        assertEquals(0L, orphanMembers())
        assertEquals(listOf("fresh signal", "old kept signal"), descriptions())
    }
}
