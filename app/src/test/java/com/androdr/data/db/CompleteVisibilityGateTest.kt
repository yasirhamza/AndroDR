package com.androdr.data.db

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * Q1 visibility gate (spec §5.1, §9 Q1): every DAO `@Query` naming `telemetry_record`,
 * `scan_record`, `scan_finding` or `forensic_timeline` applies a visibility fragment
 * ([VisibleFact], [CompleteScan], [VisibleRow]) or is on the writer/deleter allow-list below.
 */
@RunWith(RobolectricTestRunner::class)
class CompleteVisibilityGateTest {

    private val guardedTables = Regex("\\b(telemetry_record|scan_record|scan_finding|forensic_timeline)\\b")

    private val visibilityTokens = listOf(
        "\${VisibleFact.SQL}", "\${VisibleFact.PINNED_ORPHAN}", "\${CompleteScan.SQL}", "\${VisibleRow.SQL}",
    )

    /** Writers, deleters and current-scan reads (AtomReader's current-scan reads join this list in Phase C). */
    private val writerDeleterAllowList = setOf(
        "TelemetryFactDao.idsFor", "TelemetryFactDao.liveObserved", "TelemetryFactDao.deleteUnobservedUnpinned",
        "TelemetryFactDao.unobservedUnpinnedAfter", "TelemetryFactDao.bodyHashesOf",
        "TelemetryFactDao.idsBySourceKey", "RecordBodyDao.deleteUnreferenced",
        "ScanObservationDao.factIdsAfter", "ScanObservationDao.deleteForScan", "ScanObservationDao.deleteThrough",
        "ScanObservationDao.factIdsForOrdinals",
        "ForensicTimelineEventDao.deleteOlderThan", "ForensicTimelineEventDao.deleteBySource",
        "ForensicTimelineEventDao.deleteByScanId", "ForensicTimelineEventDao.deleteAll",
        // Writer-side dedup lookups over everything already emitted (hidden rows included on purpose).
        "ForensicTimelineEventDao.getInstalledPackagesAlreadyEmitted",
        "ForensicTimelineEventDao.getAdminGrantedPackagesAlreadyEmitted",
        "ForensicTimelineEventDao.getDistinctScanIdsBySource",
    )

    /**
     * Pre-store Timeline reads. No writer creates a non-COMPLETE scan's timeline rows before
     * Phase B, so these are safe today; Task C2 moves each onto [VisibleRow] and empties this.
     */
    private val legacyTimelineReadsUntilC2 = setOf(
        "ForensicTimelineEventDao.getRecentEvents", "ForensicTimelineEventDao.getEventsBySource",
        "ForensicTimelineEventDao.getEventsBySourceForScan", "ForensicTimelineEventDao.getEventsByPackage",
        "ForensicTimelineEventDao.getEventsInRange", "ForensicTimelineEventDao.getDistinctSources",
        "ForensicTimelineEventDao.getDistinctPackages", "ForensicTimelineEventDao.getAllForExport",
        "ForensicTimelineEventDao.getEventsSince", "ForensicTimelineEventDao.getEventsSinceExcludingTelemetrySource",
    )

    private data class DaoQuery(val owner: String, val name: String, val sql: String) {
        val id get() = "$owner.$name"
    }

    private fun root(): File = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
        .first { it.isDirectory }

    private val queryRe = Regex(
        "@Query\\(\\s*((?:\"\"\"[\\s\\S]*?\"\"\"|\"(?:[^\"\\\\]|\\\\.)*\")(?:\\s*\\+\\s*\"(?:[^\"\\\\]|\\\\.)*\")*)" +
            "\\s*\\)\\s*(?:@\\w+(?:\\([^)]*\\))?\\s*)*(?:suspend\\s+)?fun\\s+(\\w+)"
    )

    private fun queries(src: String, owner: String): List<DaoQuery> =
        queryRe.findAll(src).map { DaoQuery(owner, it.groupValues[2], it.groupValues[1]) }.toList()

    private fun daoQueries(): List<DaoQuery> = root().walkTopDown().filter { it.extension == "kt" }.flatMap { f ->
        val src = f.readText()
        val owner = Regex("interface\\s+(\\w+)").find(src)?.groupValues?.get(1) ?: f.nameWithoutExtension
        queries(src, owner)
    }.toList()

    private fun violations(all: List<DaoQuery>, allow: Set<String>): List<String> = all
        .filter { guardedTables.containsMatchIn(it.sql) && it.id !in allow }
        .filter { q -> visibilityTokens.none { q.sql.contains(it) } }
        .map { it.id }

    @Test
    fun `every guarded query applies the visibility rule or is allow-listed`() {
        val all = daoQueries()
        assertTrue("found only ${all.size} queries", all.size > 40)
        val bad = violations(all, writerDeleterAllowList + legacyTimelineReadsUntilC2)
        assertTrue("queries missing the COMPLETE visibility rule:\n" + bad.joinToString("\n"), bad.isEmpty())
    }

    @Test
    fun `CompleteScan is only used with the scan joined as s on the observation`() {
        val joined = listOf("ScanResult s ON s.id = ", "\$OBS_FROM")
        val bad = daoQueries()
            .filter { q -> q.sql.contains("\${CompleteScan.SQL}") && joined.none { q.sql.contains(it) } }
        assertTrue(bad.joinToString { it.id }, bad.isEmpty())
    }

    @Test
    fun `allow-list entries all still name guarded queries`() {
        val ids = daoQueries().filter { guardedTables.containsMatchIn(it.sql) }.map { it.id }.toSet()
        val stale = (writerDeleterAllowList + legacyTimelineReadsUntilC2) - ids
        assertTrue("stale allow-list entries: $stale", stale.isEmpty())
    }

    @Test
    fun `gate detects an unguarded read and accepts a guarded one`() {
        val src = "interface D {\n @Query(\"SELECT * FROM scan_record o WHERE o.scanId = :id\")\n" +
            " suspend fun bad(id: Long): List<X>\n @Query(\n \"SELECT * FROM scan_record o JOIN ScanResult s \" +\n" +
            " \"ON s.id = o.scanId WHERE \${CompleteScan.SQL}\"\n )\n suspend fun good(): List<X>\n" +
            " @Query(\"SELECT 1 FROM ScanResult\")\n fun other(): Int\n}"
        val qs = queries(src, "D")
        assertEquals(listOf("bad", "good", "other"), qs.map { it.name })
        assertEquals(listOf("D.bad"), violations(qs, emptySet()))
    }

    @Test
    fun `VisibleRow shows persistent, scan-less and COMPLETE-scan rows only`() = runBlocking {
        val db = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext<Context>(),
            AppDatabase::class.java).allowMainThreadQueries().build()
        try {
            val states = listOf(1L to ScanState.COMPLETE, 2L to ScanState.IN_PROGRESS, 3L to ScanState.DELETING)
            for ((id, state) in states) {
                db.scanResultDao().insert(ScanResult(id = id, timestamp = id, findings = emptyList(),
                    bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0, state = state))
            }
            val dao = db.forensicTimelineEventDao()
            fun row(desc: String, scan: Long, persistent: Boolean = false) = ForensicTimelineEvent(
                startTimestamp = 1L, source = "s", category = "c", description = desc, scanResultId = scan,
                persistent = persistent)
            dao.insertAll(listOf(row("complete", 1L), row("progress", 2L), row("deleting", 3L), row("none", -1L),
                row("audit", 3L, persistent = true), row("gone", 99L)))
            val visible = db.openHelper.readableDatabase
                .query("SELECT r.description FROM forensic_timeline r WHERE ${VisibleRow.SQL} ORDER BY r.id")
                .use { c -> buildList { while (c.moveToNext()) add(c.getString(0)) } }
            assertEquals(listOf("complete", "none", "audit"), visible)
        } finally {
            db.close()
        }
    }
}
