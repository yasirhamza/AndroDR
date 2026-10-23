package com.androdr.data.repo

import androidx.room.withTransaction
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanState
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
    private val deleter = TimelineRowDeleter(f.db.forensicTimelineEventDao(), f.store)

    @After fun tearDown() = f.close()

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
            row() to { deleter.allNonPersistent() },
        )
        for ((r, delete) in paths) {
            pinnedOrphan(r)
            f.db.withTransaction { delete() }
            assertEquals(0L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
            assertEquals(0L, facts())
            assertEquals(0L, f.count("SELECT COUNT(*) FROM record_body"))
        }
    }

    @Test
    fun `persistent rows survive scan deletion and clear-all, and keep their pin`() = runBlocking {
        pinnedOrphan(row(scan = 7L).copy(persistent = true))
        f.db.withTransaction { deleter.byScanId(7L) }
        f.db.withTransaction { deleter.allNonPersistent() }
        assertEquals(1L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
        assertEquals(1L, facts())
    }

    @Test
    fun `no production code calls a raw forensic_timeline delete except TimelineRowDeleter`() {
        val root = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
            .first { it.isDirectory }
        val raw = Regex("\\.(deleteOlderThan|deleteBySource|deleteByScanId|deleteAllNonPersistent)\\(")
        val offenders = root.walkTopDown().filter { it.extension == "kt" && it.name != "TimelineRowDeleter.kt" }
            .flatMap { file ->
                file.readLines().withIndex()
                    .filter { (_, line) -> raw.containsMatchIn(line) && "dnsEventDao" !in line }
                    .map { (i, line) -> "${file.name}:${i + 1}: ${line.trim()}" }
            }.toList()
        assertTrue("raw timeline deletes bypass the pin release:\n" + offenders.joinToString("\n"), offenders.isEmpty())
    }
}
