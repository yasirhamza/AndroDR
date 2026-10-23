package com.androdr.data.repo

import androidx.room.withTransaction
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
import com.androdr.data.model.SignalMember
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.StoreFixture.Companion.app
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * A5 carried rule (spec §5.1 Pins): every `forensic_timeline` delete releases the facts its rows
 * pinned, in the same transaction — through [TimelineRowDeleter], the only caller of the raw deletes.
 */
@RunWith(RobolectricTestRunner::class)
class TimelineRowDeleterTest {
    private val f = StoreFixture()
    private val deleter = TimelineRowDeleter(f.db.forensicTimelineEventDao(), f.store, f.db.signalMemberDao())

    @After fun tearDown() = f.close()

    private companion object {
        const val DAY = 24L * 60 * 60 * 1000
    }

    /** A fact pinned only by one Timeline row (its observation is gone, its scan deleted). */
    private suspend fun pinnedOrphan(row: ForensicTimelineEvent): Long {
        f.scan(1L, ScanState.COMPLETE)
        val id = f.persist(1L, "app_scanner", listOf(app("com.pinned"))).factIdByChunkIndex.single()
        f.db.forensicTimelineEventDao().insert(row.copy(recordId = id))
        f.store.deleteScanTelemetry(1L)
        f.db.scanResultDao().deleteById(1L)
        assertEquals("the pin keeps it", 1L, f.count("SELECT COUNT(*) FROM telemetry_record"))
        return id
    }

    private fun row(source: String = "s", scan: Long = 7L, createdAt: Long = 10L) = ForensicTimelineEvent(
        startTimestamp = 1L, source = source, category = "c", description = "d", scanResultId = scan,
        createdAt = createdAt)

    private fun facts() = f.count("SELECT COUNT(*) FROM telemetry_record")

    @Test
    fun `each delete path releases the facts its rows pinned`() = runBlocking {
        val paths: List<Pair<ForensicTimelineEvent, suspend () -> Unit>> = listOf(
            row(createdAt = 10L) to { deleter.olderThan(11L) },
            row(source = "intrusion_log") to { deleter.bySource("intrusion_log") },
            row(scan = 7L) to { deleter.byScanId(7L) },
            row(scan = 404L) to { deleter.unownedNonPersistent() },
            row(scan = -1L) to { deleter.unownedNonPersistent() },
        )
        for ((r, delete) in paths) {
            pinnedOrphan(r)
            f.db.withTransaction { delete() }
            assertEquals(0L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
            assertEquals(0L, facts())
            assertEquals(0L, f.count("SELECT COUNT(*) FROM record_body"))
        }
    }

    /**
     * Spec §5.4/§5.6: a signal row is deleted together with its `signal_member` rows, by every delete
     * path (the 30-day prune included), and the facts those members alone pinned are released in the
     * same transaction. Another signal's members are untouched.
     */
    @Test
    fun `each delete path takes a deleted signal's members with it and releases their facts`() = runBlocking {
        val dao = f.db.forensicTimelineEventDao()
        val survivor = dao.insert(row(source = "kept", scan = 1L, createdAt = 1_000L).copy(kind = "signal",
            persistent = true))
        f.db.signalMemberDao().insertAll(listOf(SignalMember(survivor, SignalMember.KIND_ROW, 5L)))
        for ((r, delete) in deletePaths()) {
            f.scan(1L, ScanState.COMPLETE)
            val fact = f.persist(1L, "app_scanner", listOf(app("com.member"))).factIdByChunkIndex.single()
            val sig = dao.insert(r.copy(kind = "signal"))
            f.db.signalMemberDao().insertAll(listOf(SignalMember(sig, SignalMember.KIND_FACT, fact),
                SignalMember(sig, SignalMember.KIND_ROW, 77L)))
            f.store.deleteScanTelemetry(1L)
            f.db.scanResultDao().deleteById(1L)
            assertEquals("the member pins the fact", 1L, facts())

            f.db.withTransaction { delete() }

            assertEquals(0L, f.count("SELECT COUNT(*) FROM signal_member WHERE signalRowId = $sig"))
            assertEquals("the fact its member pinned is released", 0L, facts())
            assertEquals("another signal's members stay", 1L,
                f.count("SELECT COUNT(*) FROM signal_member WHERE signalRowId = $survivor"))
            assertEquals("no delete path leaves an orphan member", 0L, orphans())
        }
    }

    /** Every TimelineRowDeleter path (prune, import/usage sweeps, scan delete, clear-all) and a row it deletes. */
    private fun deletePaths(): List<Pair<ForensicTimelineEvent, suspend () -> Unit>> = listOf(
        row(createdAt = 10L) to { deleter.olderThan(11L) },
        row(source = "intrusion_log") to { deleter.bySource("intrusion_log") },
        row(source = "usage_stats").copy(startTimestamp = 50L) to { deleter.bySourceBetween("usage_stats", 40L, 60L) },
        row(scan = 7L) to { deleter.byScanId(7L) },
        row(scan = 404L) to { deleter.unownedNonPersistent() },
    )

    private fun orphans() = f.count(
        "SELECT COUNT(*) FROM signal_member m WHERE NOT EXISTS " +
            "(SELECT 1 FROM forensic_timeline s WHERE s.id = m.signalRowId)"
    )

    /**
     * Review I-2: a delete removes members by the ids of the signals it removes, through the
     * primary-key prefix. No statement any delete path runs against signal_member may scan it
     * (a full scan per delete would run inside every live `finish`).
     */
    @Test
    fun `no delete path scans signal_member`() = runBlocking {
        val dao = f.db.forensicTimelineEventDao()
        for ((r, delete) in deletePaths()) {
            val sig = dao.insert(r.copy(kind = "signal"))
            f.db.signalMemberDao().insertAll(listOf(SignalMember(sig, SignalMember.KIND_ROW, 1L)))
            f.sql.clear()
            f.db.withTransaction { delete() }
            val recorded = synchronized(f.sql) { f.sql.toList() }
            val statements = recorded.filter { it.contains("signal_member") }.distinct()
            assertTrue("the path touched signal_member: $recorded", statements.isNotEmpty())
            for (stmt in statements) {
                val args = arrayOfNulls<Any>(stmt.count { it == '?' }).apply { fill(1L) }
                val plan = f.db.openHelper.readableDatabase.query("EXPLAIN QUERY PLAN $stmt", args).use { c ->
                    buildList { while (c.moveToNext()) add(c.getString(c.columnCount - 1)) }
                }
                assertTrue("full scan of signal_member: $stmt -> $plan",
                    plan.none { Regex("""SCAN( TABLE)? signal_member\b""").containsMatchIn(it) })
                // The composite primary key (signalRowId, kind, refId) is SQLite's autoindex.
                assertTrue("searches by the primary key: $stmt -> $plan", plan.any {
                    it.startsWith("SEARCH") && it.contains("signal_member") &&
                        (it.contains("PRIMARY KEY") || it.contains("sqlite_autoindex_signal_member_1")) &&
                        it.contains("signalRowId=?")
                })
            }
            assertEquals(0L, orphans())
        }
    }

    @Test
    fun `the 30-day prune keeps a 31-day-old persistent row and removes a non-persistent one`() = runBlocking {
        val now = 100L * DAY
        val old = now - 31 * DAY
        val dao = f.db.forensicTimelineEventDao()
        f.scan(7L, ScanState.COMPLETE) // the rows' scan: getAllForExport shows visible rows only
        dao.insert(row(createdAt = old).copy(description = "interrupted", persistent = true))
        dao.insert(row(createdAt = old).copy(description = "stale"))
        dao.insert(row(createdAt = now).copy(description = "fresh"))
        f.db.withTransaction { deleter.olderThan(now - 30 * DAY) }
        assertEquals(listOf("fresh", "interrupted"), dao.getAllForExport().map { it.description }.sorted())
    }

    @Test
    fun `clear-all keeps rows of a scan that still exists`() = runBlocking {
        f.scan(7L, ScanState.COMPLETE)
        f.db.forensicTimelineEventDao().insert(row(scan = 7L))
        f.db.forensicTimelineEventDao().insert(row(scan = -1L))
        f.db.withTransaction { deleter.unownedNonPersistent() }
        assertEquals(listOf(7L), f.db.forensicTimelineEventDao().getAllForExport().map { it.scanResultId })
    }

    @Test
    fun `persistent rows survive scan deletion and clear-all, and keep their pin`() = runBlocking {
        pinnedOrphan(row(scan = 7L).copy(persistent = true))
        f.db.withTransaction { deleter.byScanId(7L) }
        f.db.withTransaction { deleter.unownedNonPersistent() }
        f.db.withTransaction { deleter.olderThan(Long.MAX_VALUE) }
        assertEquals(1L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
        assertEquals(1L, facts())
    }

    @Test
    fun `no production code calls a raw forensic_timeline delete except TimelineRowDeleter`() {
        val root = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
            .first { it.isDirectory }
        val raw = Regex("\\.(deleteOlderThan|deleteBySource|deleteByScanId|deleteUnownedNonPersistent)\\(")
        val offenders = root.walkTopDown().filter { it.extension == "kt" && it.name != "TimelineRowDeleter.kt" }
            .flatMap { file ->
                file.readLines().withIndex()
                    .filter { (_, line) -> raw.containsMatchIn(line) && "dnsEventDao" !in line }
                    .map { (i, line) -> "${file.name}:${i + 1}: ${line.trim()}" }
            }.toList()
        assertTrue("raw timeline deletes bypass the pin release:\n" + offenders.joinToString("\n"), offenders.isEmpty())
    }
}
