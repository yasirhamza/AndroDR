package com.androdr.scanner

import android.net.Uri
import com.androdr.data.model.TelemetryState
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * F2, Phase A half (telemetry store §9): every triggered finding row a real writer writes on a
 * stored service carries a non-null `level` and a `recordId` that resolves to a fact this scan
 * observed. The fixtures put the finding in a second chunk (`firstOrdinal > 0`), so chunk-relative
 * indexing is exercised. `FAILED` scans (evaluate-only, nothing stored) are exempt.
 */
@RunWith(RobolectricTestRunner::class)
class FindingRowRecordIdTest {
    private val uri = mockk<Uri>(relaxed = true)

    private data class Row(val scanId: Long, val ruleId: String, val recordId: Long?, val level: String?)

    private fun findingRows(f: OrchestratorFixture, failed: Boolean): List<Row> = f.db.openHelper.readableDatabase
        .query(
            "SELECT r.scanResultId, r.ruleId, r.recordId, r.level FROM forensic_timeline r " +
                "JOIN ScanResult s ON s.id = r.scanResultId WHERE r.ruleId != '' AND r.kind != 'signal' " +
                "AND (s.telemetryState = '${TelemetryState.FAILED.name}') = ${if (failed) 1 else 0}"
        ).use { c ->
            generateSequence {
                if (!c.moveToNext()) null
                else Row(c.getLong(0), c.getString(1), if (c.isNull(2)) null else c.getLong(2),
                    if (c.isNull(3)) null else c.getString(3))
            }.toList()
        }

    private fun assertResolvable(f: OrchestratorFixture, expectedRows: Int) {
        val rows = findingRows(f, failed = false)
        assertEquals(rows.toString(), expectedRows, rows.size)
        for (r in rows) {
            assertNotNull("level on $r", r.level)
            assertNotNull("recordId on $r", r.recordId)
            assertEquals("recordId of $r is a fact this scan observed", 1L,
                f.count("SELECT COUNT(*) FROM scan_record WHERE scanId = ${r.scanId} AND recordId = ${r.recordId}"))
        }
    }

    private fun securityLines(n: Int, hitFrom: Int) = (0 until n).map {
        val tag = if (it >= hitFrom) "hit_cmd" else "other"
        """{"security_event":{"event_id":$it,"event_time":${1787400000000L + it},"$tag":{"n":$it}}}"""
    }

    private val ilEngine get() = IntrusionLogZips.engine(
        IntrusionLogZips.rule("androdr-f2-sec", "security_log", "tag_name", "hit_cmd", "high"))

    @Test
    fun `F2 - intrusion-log finding rows past the first chunk resolve their fact`() = runBlocking {
        val zip = IntrusionLogZips.zip("2026-08-22.txt" to securityLines(5_003, hitFrom = 5_001))
        IntrusionLogZips.fixture(ilEngine) { zip }.use { f ->
            val result = f.orchestrator.analyzeIntrusionLog(uri)
            assertEquals(listOf(5_001, 5_002), f.findingsOf(result.write!!.scan.id).map { it.ordinal })
            assertResolvable(f, expectedRows = 2)
        }
    }

    @Test
    fun `F2 - live finding rows past the first chunk resolve their fact`() = runBlocking {
        val engine = IntrusionLogZips.engine(
            IntrusionLogZips.rule("androdr-f2-app", "app_scanner", "package_name", "com.app5001", "critical"))
        OrchestratorFixture(engine = engine).use { f ->
            coEvery { f.appScanner.collectTelemetry() } returns (0..5_001).map { OrchestratorFixture.app("com.app$it") }
            val scan = f.orchestrator.runFullScan()
            assertEquals(5_001, scan.findings.single().ordinal)
            assertResolvable(f, expectedRows = 1)
        }
    }

    @Test
    fun `F2 - bug-report finding rows resolve their fact`() = runBlocking {
        val engine = IntrusionLogZips.engine(IntrusionLogZips.rule("androdr-f2-br", "package_install_history",
            "package_name", "com.example.alpha", "medium"))
        OrchestratorFixture(engine = engine, bugReportAnalyzer = BugReportFixtures.analyzer()).use { f ->
            val result = f.orchestrator.analyzeBugReport(uri)
            val hits = f.findingsOf(result.write!!.scan.id).count { it.triggered }
            assertTrue("the fixture has alpha install-history records", hits >= 1)
            assertResolvable(f, expectedRows = hits)
        }
    }

    /** Evaluate-only (reserve breached): findings are kept with no fact; the scan is FAILED and exempt. */
    @Test
    fun `F2 - FAILED scans are exempt (their finding rows have no fact)`() = runBlocking {
        val zip = IntrusionLogZips.zip("2026-08-22.txt" to securityLines(3, hitFrom = 1))
        IntrusionLogZips.fixture(ilEngine) { zip }.use { f ->
            f.w.freeBytes = 0L
            val result = f.orchestrator.analyzeIntrusionLog(uri)
            assertEquals(TelemetryState.FAILED, result.write!!.telemetryState)
            val failedRows = findingRows(f, failed = true)
            assertEquals(2, failedRows.size)
            assertTrue(failedRows.all { it.recordId == null && it.level != null })
            assertResolvable(f, expectedRows = 0)
        }
    }
}
