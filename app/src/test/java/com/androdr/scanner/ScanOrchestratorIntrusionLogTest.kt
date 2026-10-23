package com.androdr.scanner

import com.androdr.data.db.getAllForExport
import android.net.Uri
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.CorrelationRule
import com.androdr.sigma.CorrelationType
import com.androdr.sigma.IntrusionLogRecordBuilders
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The intrusion-log import through its writer session (#342, telemetry store §5.2): events stored
 * as facts only (C3: no event rows, no replace-on-reimport), the findings cap, failure honesty, and
 * the source stamp — on a real database. The analyzer is mocked where a test needs exact records;
 * it hands them over the way the real one does, per type in chunks of at most 5,000.
 */
@RunWith(RobolectricTestRunner::class)
class ScanOrchestratorIntrusionLogTest {

    private val engine = IntrusionLogZips.engine(
        IntrusionLogZips.rule("androdr-il-sec", "security_log", "tag_name", "adb_shell_cmd", "high"),
        IntrusionLogZips.rule("androdr-il-crit", "security_log", "tag_name", "critical_cmd", "critical"),
    )
    private val f = OrchestratorFixture(engine = engine)
    private val uri = mockk<Uri>(relaxed = true)

    @After fun tearDown() = f.close()

    // ---------- fixtures ----------

    private fun dns(ts: Long) = ImportedDnsEvent(
        event = DnsEvent(timestamp = ts, domain = "d$ts.example.com", appUid = 10, appName = "com.a",
            isBlocked = false, reason = null),
        resolvedIps = emptyList()
    )

    private fun net(ts: Long) = NetworkTelemetry(
        destinationIp = "10.0.0.1", destinationPort = 443, protocol = null, appUid = -1, appName = "com.b",
        timestamp = ts, source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L
    )

    private fun sec(ts: Long, tag: String = "adb_shell_cmd") = SecurityLogEvent(
        timestamp = ts, tag = 210002, tagName = tag, securityData = listOf("id"),
        source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L
    )

    /** The mocked analyzer hands [dns], [net] and [sec] over in chunks, keyed by position. */
    private fun analyzerHandsOver(
        dns: List<ImportedDnsEvent> = emptyList(),
        net: List<NetworkTelemetry> = emptyList(),
        sec: List<SecurityLogEvent> = emptyList(),
    ) {
        coEvery { f.intrusionLogAnalyzer.analyze(any(), any()) } coAnswers {
            val chunks = secondArg<IntrusionLogChunks>()
            dns.chunked(ChunkedScanWriter.CHUNK_SIZE).forEachIndexed { c, part ->
                val keys = part.indices.map { "dns_event ${c}_$it" }
                chunks.dns(part, IntrusionLogRecordBuilders.importedDns(part, keys))
            }
            net.chunked(ChunkedScanWriter.CHUNK_SIZE).forEachIndexed { c, part ->
                val keys = part.indices.map { "connect_event ${c}_$it" }
                chunks.connect(part, IntrusionLogRecordBuilders.network(part, keys))
            }
            sec.chunked(ChunkedScanWriter.CHUNK_SIZE).forEachIndexed { c, part ->
                val keys = part.indices.map { "security ${c}_$it" }
                chunks.security(part, IntrusionLogRecordBuilders.securityLog(part, keys))
            }
            IntrusionLogScan(IntrusionLogStats(dns.size, net.size, sec.size, 0, 0, null, null), emptyList())
        }
    }

    private fun row(source: String, scanId: Long, kind: String = "event") = ForensicTimelineEvent(
        startTimestamp = 1L, source = source, category = "security_event", description = "prior", kind = kind,
        scanResultId = scanId,
    )

    private suspend fun rows() = f.timelineDao.getAllForExport()

    /**
     * Every row present as (source, scanResultId), visible or not: the sweep tests' prior imports
     * have no ScanResult row, so `VisibleRow` (C2) hides their rows from the DAO reads.
     */
    private fun allRows(): List<ForensicTimelineEvent> = f.db.openHelper.readableDatabase
        .query("SELECT source, scanResultId FROM forensic_timeline ORDER BY id").use { c ->
            generateSequence {
                if (c.moveToNext()) {
                    ForensicTimelineEvent(startTimestamp = 0L, source = c.getString(0), category = "",
                        description = "", scanResultId = c.getLong(1))
                } else {
                    null
                }
            }.toList()
        }

    // ---------- no replace-on-reimport (C3, spec §5.2) ----------

    /**
     * Replace-on-reimport is removed in C3: an import deletes no other scan's rows — neither a prior
     * import's finding rows and signals nor anyone else's — and writes no event rows of its own.
     */
    @Test
    fun `an import deletes no other scan's rows and writes no event rows`() = runBlocking {
        val prior = listOf(
            row("intrusion_log", 11L), row("intrusion_log_analysis", 11L),
            row("sigma_correlation_engine", 11L, kind = "signal"), row("intrusion_log", 22L),
            row("intrusion_log", -1L), row("app_scanner", 33L),
        )
        f.timelineDao.insertAll(prior)
        analyzerHandsOver(sec = listOf(sec(5L)))

        f.orchestrator.analyzeIntrusionLog(uri)

        val scanId = f.scans().single().id
        val left = allRows()
        assertEquals("every other row stays", prior.map { it.source to it.scanResultId },
            left.filter { it.scanResultId != scanId }.map { it.source to it.scanResultId })
        assertEquals("the import wrote its finding row only", listOf("intrusion_log_analysis"),
            left.filter { it.scanResultId == scanId }.map { it.source })
    }

    /**
     * #342 B1: a finish that fails keeps every other row, the import is removed, and the failure is
     * SURFACED as the honest [ScanOrchestrator.IntrusionLogPersistException].
     */
    @Test
    fun `a failed finish deletes nothing and surfaces the failure`() = runBlocking {
        f.timelineDao.insertAll(listOf(row("intrusion_log", 11L)))
        coEvery { f.intrusionLogAnalyzer.analyze(any(), any()) } coAnswers {
            val chunks = secondArg<IntrusionLogChunks>()
            chunks.security(listOf(sec(5L)), IntrusionLogRecordBuilders.securityLog(listOf(sec(5L)), listOf("k")))
            // A delete marks the open import DELETING: the guarded finish rolls everything back.
            f.db.openHelper.writableDatabase.execSQL("UPDATE ScanResult SET state = 'DELETING'")
            IntrusionLogScan(IntrusionLogStats(0, 0, 1, 0, 0, null, null), emptyList())
        }

        val thrown = runCatching { f.orchestrator.analyzeIntrusionLog(uri) }.exceptionOrNull()

        assertTrue("honest failure: $thrown", thrown is ScanOrchestrator.IntrusionLogPersistException)
        assertEquals("the prior import survives", listOf(11L), allRows().map { it.scanResultId })
        assertEquals("the failed import is removed", 0L, f.count("SELECT COUNT(*) FROM ScanResult"))
        assertEquals(0L, f.count("SELECT COUNT(*) FROM scan_record"))
    }

    /**
     * #356: an ANALYSIS failure aborts the session: nothing is deleted or kept, and the error
     * reaches the ViewModel's error card.
     */
    @Test
    fun `an analysis failure deletes and persists nothing`() = runBlocking {
        f.timelineDao.insertAll(listOf(row("intrusion_log", 11L)))
        coEvery { f.intrusionLogAnalyzer.analyze(any(), any()) } throws
            IntrusionLogAnalyzer.IntrusionLogAnalysisException(RuntimeException("unreadable zip"))

        val thrown = runCatching { f.orchestrator.analyzeIntrusionLog(uri) }.exceptionOrNull()

        assertTrue("propagated: $thrown", thrown is IntrusionLogAnalyzer.IntrusionLogAnalysisException)
        assertEquals(listOf(11L), allRows().map { it.scanResultId })
        assertEquals(0L, f.count("SELECT COUNT(*) FROM ScanResult"))
    }

    /** #356: imports are labeled, not passed off as live scans of this device. */
    @Test
    fun `persisted ScanResult is stamped INTRUSION_LOG_IMPORT`() = runBlocking {
        analyzerHandsOver(sec = listOf(sec(5L)))
        f.orchestrator.analyzeIntrusionLog(uri)
        assertEquals(TelemetrySource.INTRUSION_LOG_IMPORT, f.scans().single().source)
    }

    // ---------- events are store-only (C3) ----------

    /** Every record is an observation; the only rows are the finding rows, with the import's stamps. */
    @Test
    fun `records are observations and the only rows are finding rows with import sources`() = runBlocking {
        analyzerHandsOver(dns = listOf(dns(10L), dns(20L)), net = listOf(net(30L)), sec = listOf(sec(40L)))

        f.orchestrator.analyzeIntrusionLog(uri)

        val scanId = f.scans().single().id
        assertEquals(4L, f.count("SELECT COUNT(*) FROM scan_record WHERE scanId = $scanId"))
        val written = f.db.openHelper.readableDatabase
            .query("SELECT source, startTimestamp FROM forensic_timeline ORDER BY id").use { c ->
                generateSequence { if (c.moveToNext()) c.getString(0) to c.getLong(1) else null }.toList()
            }
        assertEquals(listOf("intrusion_log_analysis" to 40L), written)
        assertTrue(rows().all {
            it.telemetrySource == TelemetrySource.INTRUSION_LOG_IMPORT && it.scanResultId == scanId
        })
    }

    // ---------- no findings cap (D2, spec §5.5; the #342 B3 cap was 1,000) ----------

    /** Every triggered finding is a scan_finding row with its finding row; nothing is dropped. */
    @Test
    fun `more than 1000 triggered findings are all stored`() = runBlocking {
        val n = 1_030
        val criticals = (1L..3L).map { sec(5_000L + it, "critical_cmd") }
        analyzerHandsOver(sec = (1L..n.toLong()).map { sec(it) } + criticals)

        val result = f.orchestrator.analyzeIntrusionLog(uri)

        val persisted = f.scans().single()
        val findings = f.findingsOf(persisted.id)
        assertEquals("no cap", n + 3, findings.size)
        assertTrue(findings.all { it.triggered })
        assertEquals(3, findings.count { it.ruleId == "androdr-il-crit" })
        assertEquals(n + 3, rows().count { it.source == "intrusion_log_analysis" })
        assertEquals(n + 3, persisted.triggeredCount)
        assertEquals("critical", persisted.maxLevel)
        assertEquals(n + 3, result.stats.triggeredFindingCount)
    }

    // ---------- S2 and Interim re-import, through the real parser ----------

    private val idLess = """{"security_event":{"event_time":1787400345600,"tag":210002,"data":["ls"]}}"""
    private val withId = """{"security_event":{"event_id":4,"event_time":1787400345700,"tag":210002,"data":["id"]}}"""

    /** S2: the same id-less line twice yields one observation and ONE finding. */
    @Test
    fun `S2 - an id-less line repeated in a log is one observation and one finding`() = runBlocking {
        val zip = IntrusionLogZips.zip("2026-08-22.txt" to listOf(idLess, idLess), "2026-08-23.txt" to listOf(idLess))
        IntrusionLogZips.fixture(engine) { zip }.use { real ->
            val result = real.orchestrator.analyzeIntrusionLog(uri)
            assertEquals(1L, real.count("SELECT COUNT(*) FROM scan_record"))
            assertEquals(1, real.findingsOf(result.write!!.scan.id).count { it.triggered })
            assertEquals("no event row (C3)", 0, real.timelineDao.getAllForExport().count { it.ruleId.isEmpty() })
            assertEquals(1, result.stats.securityEventCount)
            assertEquals(2, result.stats.duplicatesCollapsed)
        }
    }

    /** Re-importing the same log adds no fact ("0 new") and writes no event rows (C3). */
    @Test
    fun `re-importing the same log shows 0 new facts and writes no event rows`() = runBlocking {
        val zip = IntrusionLogZips.zip("2026-08-22.txt" to listOf(idLess, withId))
        IntrusionLogZips.fixture(engine) { zip }.use { real ->
            real.orchestrator.analyzeIntrusionLog(uri)
            val facts = real.count("SELECT COUNT(*) FROM telemetry_record")
            Thread.sleep(2) // distinct scan ids (epoch ms)

            val again = real.orchestrator.analyzeIntrusionLog(uri)

            assertEquals("the card shows 0 new", 0, again.write!!.newFacts)
            assertEquals(2, again.write!!.alreadyStored)
            assertEquals("no new facts", facts, real.count("SELECT COUNT(*) FROM telemetry_record"))
            assertEquals("two observation sets", 4L, real.count("SELECT COUNT(*) FROM scan_record"))
            assertTrue("finding rows only", real.timelineDao.getAllForExport().all { it.ruleId.isNotEmpty() })
        }
    }

    // ---------- live-scan correlation lookback excludes imports (#342 B2) ----------

    /**
     * #342 B2: a LIVE scan's correlation lookback must NOT bind imported intrusion-log rows: they
     * carry their own historical time, and a signal they produced would be stamped with the live
     * scan's id, unreachable by the intrusion-log sweep (an orphan signal).
     */
    @Test
    fun `live scan lookback leaves imported rows out of correlation`() = runBlocking {
        OrchestratorFixture().use { live ->
            every { live.engine.getCorrelationRules() } returns listOf(
                CorrelationRule(id = "corr-1", title = "t", type = CorrelationType.TEMPORAL,
                    referencedRuleIds = listOf("a", "b"), timespanMs = 3_600_000L, groupBy = emptyList(),
                    minEvents = 1, severity = "high", displayLabel = "l")
            )
            val now = System.currentTimeMillis()
            // Both scans COMPLETE, so only the import source keeps the imported row out (not visibility).
            live.w.f.scan(8L, com.androdr.data.model.ScanState.COMPLETE)
            live.w.f.scan(9L, com.androdr.data.model.ScanState.COMPLETE)
            live.timelineDao.insertAll(listOf(
                ForensicTimelineEvent(startTimestamp = now - 1_000, source = "intrusion_log",
                    category = "dns_query", description = "imported",
                    telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT, scanResultId = 9L),
                ForensicTimelineEvent(startTimestamp = now - 1_000, source = "app_scanner",
                    category = "package_install", description = "live",
                    telemetrySource = TelemetrySource.LIVE_SCAN, scanResultId = 8L),
            ))
            every { live.engine.atomCategories() } returns mapOf("a" to "package_install", "b" to "dns_query")
            val atoms = slot<List<com.androdr.sigma.TimelineAtom>>()
            every { live.correlationEngine.evaluate(any(), capture(atoms), any(), any(), any()) } returns
                com.androdr.sigma.CorrelationResult.NONE

            live.orchestrator.runFullScan()

            assertEquals("only the live row is an atom", listOf("package_install"), atoms.captured.map { it.category })
            assertFalse(atoms.captured.any { it.telemetrySource == TelemetrySource.INTRUSION_LOG_IMPORT })
        }
    }

    // ---------- fix round 1 ----------

    /** I2: a finishing write that hits a full disk leaves nothing saved, so the import fails loudly. */
    @Test
    fun `an import whose finishing write is not saved fails with IntrusionLogPersistException`() = runBlocking {
        analyzerHandsOver(sec = listOf(sec(5L)))
        val repo = io.mockk.spyk(f.w.repo)
        f.w.repo = repo
        coEvery { repo.finish(any(), any(), any(), any(), any()) } throws
            android.database.sqlite.SQLiteFullException("database or disk is full")

        val thrown = runCatching { f.orchestrator.analyzeIntrusionLog(uri) }.exceptionOrNull()

        assertTrue("not saved is a failed import: $thrown", thrown is ScanOrchestrator.IntrusionLogPersistException)
        assertEquals(0L, f.count("SELECT COUNT(*) FROM ScanResult"))
    }

    /** M2: a writer failure inside the analyzer is a failed save, not a failed analysis. */
    @Test
    fun `a writer failure inside the analyzer surfaces as IntrusionLogPersistException`() = runBlocking {
        val zip = IntrusionLogZips.zip("2026-08-22.txt" to listOf(withId))
        IntrusionLogZips.fixture(engine) { zip }.use { real ->
            val store = io.mockk.spyk(real.w.f.store)
            real.w.store = store
            coEvery { store.persistChunk(any(), any(), any(), any(), any(), any(), any(), any(), any()) } throws
                IllegalStateException("constraint failed")

            val thrown = runCatching { real.orchestrator.analyzeIntrusionLog(uri) }.exceptionOrNull()

            assertTrue("a failed save, not a failed analysis: $thrown",
                thrown is ScanOrchestrator.IntrusionLogPersistException)
            assertTrue(generateSequence(thrown) { it.cause }.any { it is IllegalStateException &&
                it.message == "constraint failed" })
            assertEquals(0L, real.count("SELECT COUNT(*) FROM ScanResult"))
        }
    }
}
