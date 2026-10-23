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

    /** Writers, deleters and current-scan reads. */
    private val writerDeleterAllowList = setOf(
        "TelemetryFactDao.idsFor", "TelemetryFactDao.liveObserved", "TelemetryFactDao.deleteUnobservedUnpinned",
        "TelemetryFactDao.unobservedUnpinnedAfter", "TelemetryFactDao.bodyHashesOf",
        "TelemetryFactDao.idsBySourceKey", "RecordBodyDao.deleteUnreferenced",
        "ScanObservationDao.factIdsAfter", "ScanObservationDao.deleteForScan", "ScanObservationDao.deleteThrough",
        "ScanObservationDao.factIdsForOrdinals",
        "ForensicTimelineEventDao.deleteOlderThan", "ForensicTimelineEventDao.deleteByIds",
        "ForensicTimelineEventDao.deleteByScanId", "ForensicTimelineEventDao.deleteUnownedNonPersistent",
        // The pins a delete releases (TimelineRowDeleter), read just before the paired delete.
        "ForensicTimelineEventDao.recordIdsOlderThan", "ForensicTimelineEventDao.recordIdsByIds",
        "ForensicTimelineEventDao.recordIdsByScanId", "ForensicTimelineEventDao.recordIdsUnownedNonPersistent",
        // Writer-side dedup lookups over everything already emitted (hidden rows included on purpose).
        "ForensicTimelineEventDao.getInstalledPackagesAlreadyEmitted",
        "ForensicTimelineEventDao.getAdminGrantedPackagesAlreadyEmitted",
        // AtomReader (spec §5.2): the finishing scan's own rows and observations (it is IN_PROGRESS),
        // and the lookback's facts, visible as "a COMPLETE live-scan observation" (stricter than
        // VisibleFact: no pinned orphans, no import observations).
        "AtomDao.rowsForScan", "AtomDao.factsForScan", "AtomDao.liveFactsBetween",
        // The signal rows a delete is about to remove (their members go with them, by id).
        "ForensicTimelineEventDao.signalIdsOlderThan", "ForensicTimelineEventDao.signalIdsByIds",
        "ForensicTimelineEventDao.signalIdsByScanId",
        "ForensicTimelineEventDao.signalIdsUnownedNonPersistent",
        // The one-time signal_member backfill reads and rewrites every legacy signal row.
        "SignalMemberBackfillDao.legacyAfter", "SignalMemberBackfillDao.signalExists",
        "SignalMemberBackfillDao.rewrite",
        // The one-time legacy event-row cleanup (C3) selects rows of every scan by producer.
        "LegacyEventRowDao.orphanSignalIds", "LegacyEventRowDao.legacyRowsAfter",
        // The finishing transaction's scan_finding statements (spec §5.2): the scan is still IN_PROGRESS.
        "ScanFindingDao.insertFindingRows", "ScanFindingDao.clearEvidence", "ScanFindingDao.unattachedCount",
        "AlertDao.openForScan", "AlertDao.attachForScan", "AlertDao.touchForScan",
        // A scan delete's scan_finding pins and rows (TimelineRowDeleter-style: read, delete, release).
        "ScanFindingDao.recordIdsForScan", "ScanFindingDao.deleteForScan",
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

    private val literal = "\"(?:[^\"\\\\]|\\\\.)*\""
    private val constRe = Regex("const\\s+val\\s+(\\w+)\\s*=\\s*($literal(?:\\s*\\+\\s*$literal)*)")
    private val literalRe = Regex("\"((?:[^\"\\\\]|\\\\.)*)\"")
    private val bareRef = Regex("\\$\\{(\\w+)\\}|\\$(\\w+)")

    /** `const val NAME = "…" + "…"` string constants, as their concatenated literal text. */
    private fun constants(src: String): Map<String, String> = constRe.findAll(src).associate { m ->
        m.groupValues[1] to literalRe.findAll(m.groupValues[2]).joinToString("") { it.groupValues[1] }
    }

    /**
     * Inlines unqualified `$NAME` / `${NAME}` constant references (recursively), so a guarded table
     * named only inside a shared fragment such as `OBS_FROM` is still seen. Qualified visibility
     * tokens (`${VisibleFact.SQL}` …) are left in place.
     */
    private fun expand(sql: String, consts: Map<String, String>): String {
        var text = sql
        repeat(MAX_EXPANSION_DEPTH) {
            val next = bareRef.replace(text) { m -> consts[m.groupValues[1].ifEmpty { m.groupValues[2] }] ?: m.value }
            if (next == text) return text
            text = next
        }
        error("constant expansion did not converge: $sql")
    }

    private fun queries(src: String, owner: String, consts: Map<String, String>): List<DaoQuery> =
        queryRe.findAll(src).map { DaoQuery(owner, it.groupValues[2], expand(it.groupValues[1], consts)) }.toList()

    private fun sources(): List<String> =
        root().walkTopDown().filter { it.extension == "kt" }.map { it.readText() }.toList()

    private fun daoQueries(): List<DaoQuery> {
        val all = sources()
        val consts = all.fold(emptyMap<String, String>()) { acc, src -> acc + constants(src) }
        return all.flatMap { src ->
            val owner = Regex("interface\\s+(\\w+)").find(src)?.groupValues?.get(1) ?: "?"
            queries(src, owner, consts)
        }
    }

    private fun violations(all: List<DaoQuery>, allow: Set<String>): List<String> = all
        .filter { guardedTables.containsMatchIn(it.sql) && it.id !in allow }
        .filter { q -> visibilityTokens.none { q.sql.contains(it) } }
        .map { it.id }

    @Test
    fun `every guarded query applies the visibility rule or is allow-listed`() {
        val all = daoQueries()
        assertTrue("found only ${all.size} queries", all.size > 40)
        val bad = violations(all, writerDeleterAllowList)
        assertTrue("queries missing the COMPLETE visibility rule:\n" + bad.joinToString("\n"), bad.isEmpty())
    }

    @Test
    fun `CompleteScan is only used with the scan joined as s on the observation`() {
        val bad = daoQueries()
            .filter { q -> q.sql.contains("\${CompleteScan.SQL}") && !q.sql.contains("ScanResult s ON s.id = ") }
        assertTrue(bad.joinToString { it.id }, bad.isEmpty())
    }

    @Test
    fun `allow-list entries all still name guarded queries`() {
        val ids = daoQueries().filter { guardedTables.containsMatchIn(it.sql) }.map { it.id }.toSet()
        val stale = writerDeleterAllowList - ids
        assertTrue("stale allow-list entries: $stale", stale.isEmpty())
    }

    @Test
    fun `gate detects an unguarded read and accepts a guarded one`() {
        val src = "interface D {\n @Query(\"SELECT * FROM scan_record o WHERE o.scanId = :id\")\n" +
            " suspend fun bad(id: Long): List<X>\n @Query(\n \"SELECT * FROM scan_record o JOIN ScanResult s \" +\n" +
            " \"ON s.id = o.scanId WHERE \${CompleteScan.SQL}\"\n )\n suspend fun good(): List<X>\n" +
            " @Query(\"SELECT 1 FROM ScanResult\")\n fun other(): Int\n}"
        val qs = queries(src, "D", emptyMap())
        assertEquals(listOf("bad", "good", "other"), qs.map { it.name })
        assertEquals(listOf("D.bad"), violations(qs, emptySet()))
    }

    @Test
    fun `gate sees guarded tables named only through an interpolated constant`() {
        val src = "internal const val FROM_OBS = \"FROM scan_record o \" +\n" +
            "    \"JOIN ScanResult s ON s.id = o.scanId\"\n" +
            "internal const val COLS = \"o.ordinal AS ordinal\"\n" +
            "interface D {\n @Query(\"SELECT \$COLS \$FROM_OBS WHERE o.scanId = :id\")\n" +
            " suspend fun bad(id: Long): List<X>\n" +
            " @Query(\"SELECT \${COLS} \${FROM_OBS} WHERE \${CompleteScan.SQL}\")\n suspend fun good(): List<X>\n}"
        val qs = queries(src, "D", constants(src))
        assertTrue(qs.all { "scan_record" in it.sql && "\$" !in it.sql.replace("\${CompleteScan.SQL}", "") })
        assertEquals(listOf("D.bad"), violations(qs, emptySet()))
    }

    @Test
    fun `VisibleRow shows persistent, scan-less and COMPLETE-scan rows only`() = runBlocking {
        val db = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext<Context>(),
            AppDatabase::class.java).allowMainThreadQueries().build()
        try {
            val states = listOf(1L to ScanState.COMPLETE, 2L to ScanState.IN_PROGRESS, 3L to ScanState.DELETING)
            for ((id, state) in states) {
                db.scanResultDao().insert(ScanResult(id = id, timestamp = id,
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

    private companion object {
        const val MAX_EXPANSION_DEPTH = 8
    }
}
