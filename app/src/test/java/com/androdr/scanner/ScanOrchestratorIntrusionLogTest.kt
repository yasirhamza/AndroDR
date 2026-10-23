package com.androdr.scanner

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
 * The intrusion-log import through its writer session (#342, telemetry store §5.2): the
 * replace-on-reimport sweep inside the finishing transaction, the newest-N Timeline-row caps, the
 * findings cap, failure honesty, and the source stamp — on a real database. The analyzer is mocked
 * where a test needs exact records; it hands them over the way the real one does, per type in
 * chunks of at most 5,000.
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

    private fun times(category: String): List<Long> = f.db.openHelper.readableDatabase
        .query("SELECT startTimestamp FROM forensic_timeline WHERE category = '$category'").use { c ->
            generateSequence { if (c.moveToNext()) c.getLong(0) else null }.toList()
        }

    // ---------- replace-on-reimport (inside the finishing transaction, #342 B1) ----------

    /**
     * A prior import's correlation signals live under `source = "sigma_correlation_engine"` — shared
     * with the live-scan and bug-report paths, so never deleted wholesale. They are swept by SCAN ID:
     * every row of one import (raw, finding, and signal) carries that import's scanResultId.
     */
    @Test
    fun `reimport sweeps every prior import's rows by scan id and keeps other rows`() = runBlocking {
        f.timelineDao.insertAll(listOf(
            row("intrusion_log", 11L), row("intrusion_log_analysis", 11L),
            row("sigma_correlation_engine", 11L, kind = "signal"), row("intrusion_log", 22L),
            row("intrusion_log", -1L), row("app_scanner", 33L),
        ))
        analyzerHandsOver(sec = listOf(sec(5L)))

        f.orchestrator.analyzeIntrusionLog(uri)

        val left = rows()
        assertEquals(listOf("app_scanner"), left.filter { it.scanResultId != f.scans().single().id }.map { it.source })
        assertTrue("the new import's rows are written", left.any { it.source == "intrusion_log" })
    }

    /**
     * #342 B1: a finish that fails after its sweep rolls the sweep back, the import is removed, and
     * the failure is SURFACED as the honest [ScanOrchestrator.IntrusionLogPersistException].
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
        assertEquals("the prior import survives", listOf(11L), rows().map { it.scanResultId })
        assertEquals("the failed import is removed", 0L, f.count("SELECT COUNT(*) FROM ScanResult"))
        assertEquals(0L, f.count("SELECT COUNT(*) FROM scan_record"))
    }

    /**
     * #356: an ANALYSIS failure must never reach the sweep. The session is aborted, nothing is
     * deleted or kept, and the error reaches the ViewModel's error card.
     */
    @Test
    fun `an analysis failure never sweeps or persists anything`() = runBlocking {
        f.timelineDao.insertAll(listOf(row("intrusion_log", 11L)))
        coEvery { f.intrusionLogAnalyzer.analyze(any(), any()) } throws
            IntrusionLogAnalyzer.IntrusionLogAnalysisException(RuntimeException("unreadable zip"))

        val thrown = runCatching { f.orchestrator.analyzeIntrusionLog(uri) }.exceptionOrNull()

        assertTrue("propagated: $thrown", thrown is IntrusionLogAnalyzer.IntrusionLogAnalysisException)
        assertEquals(listOf(11L), rows().map { it.scanResultId })
        assertEquals(0L, f.count("SELECT COUNT(*) FROM ScanResult"))
    }

    /** #356: imports are labeled, not passed off as live scans of this device. */
    @Test
    fun `persisted ScanResult is stamped INTRUSION_LOG_IMPORT`() = runBlocking {
        analyzerHandsOver(sec = listOf(sec(5L)))
        f.orchestrator.analyzeIntrusionLog(uri)
        assertEquals(TelemetrySource.INTRUSION_LOG_IMPORT, f.scans().single().source)
    }

    // ---------- Interim: newest-N Timeline-row caps (#342 spec §7, B4) ----------

    /** Oldest-first input, so a cap that ignored ordering would keep the WRONG (oldest) events. */
    @Test
    fun `dns and connect rows are capped newest-first and security stays under its cap`() = runBlocking {
        val dnsTotal = ScanOrchestrator.DNS_PERSIST_CAP + 5
        val netTotal = ScanOrchestrator.CONNECT_PERSIST_CAP + 3
        analyzerHandsOver(
            dns = (1L..dnsTotal.toLong()).map { dns(it) },
            net = (1L..netTotal.toLong()).map { net(it) },
            sec = (1L..25L).map { sec(it, "other") },
        )

        f.orchestrator.analyzeIntrusionLog(uri)

        // getAllForExport stops at 10,000 rows, so read the rows directly.
        val dnsTimes = times("dns_query")
        val netTimes = times("network_connect")
        assertEquals(ScanOrchestrator.DNS_PERSIST_CAP, dnsTimes.size)
        assertEquals(ScanOrchestrator.CONNECT_PERSIST_CAP, netTimes.size)
        assertEquals("security below the cap is kept in full", 25, times("security_event").size)
        assertEquals("oldest kept dns is exactly at the cap boundary", 6L, dnsTimes.min())
        assertTrue("newest dns kept", dnsTotal.toLong() in dnsTimes)
        assertEquals("oldest kept connect is exactly at the cap boundary", 4L, netTimes.min())
        assertEquals("every record is stored even past the row cap", (dnsTotal + netTotal + 25).toLong(),
            f.count("SELECT COUNT(*) FROM scan_record"))
    }

    /** Interim rows equal today's newest-N (`sortedByDescending { time }.take(cap)`), ties included. */
    @Test
    fun `interim security rows equal today's newest-N with ties and carry their recordId`() = runBlocking {
        val total = ScanOrchestrator.SECURITY_PERSIST_CAP + 700
        // Few distinct times, shuffled: ties must resolve exactly as the stable sort did.
        val events = (0 until total).map { sec(1_000L + (it * 7919L) % 50, "other").copy(securityData = listOf("$it")) }
        analyzerHandsOver(sec = events)

        f.orchestrator.analyzeIntrusionLog(uri)

        val expected = events.sortedByDescending { it.timestamp }.take(ScanOrchestrator.SECURITY_PERSIST_CAP)
        val kept = rows().filter { it.category == "security_event" }
        assertEquals(expected.map { it.securityData.single() }.sorted(), kept.map { it.details }.sorted())
        assertTrue("every interim row pins its fact", kept.all { r ->
            r.recordId != null && f.count("SELECT COUNT(*) FROM telemetry_record WHERE id = ${r.recordId}") == 1L
        })
    }

    @Test
    fun `rows are findings then dns then connect then security with import sources`() = runBlocking {
        analyzerHandsOver(dns = listOf(dns(10L), dns(20L)), net = listOf(net(30L)), sec = listOf(sec(40L)))

        f.orchestrator.analyzeIntrusionLog(uri)

        val scanId = f.scans().single().id
        val written = f.db.openHelper.readableDatabase
            .query("SELECT source, category, startTimestamp FROM forensic_timeline ORDER BY id").use { c ->
                generateSequence { if (c.moveToNext()) Triple(c.getString(0), c.getString(1), c.getLong(2)) else null }
                    .toList()
            }
        assertEquals(listOf("intrusion_log_analysis") + List(4) { "intrusion_log" }, written.map { it.first })
        assertEquals(listOf("dns_query", "dns_query", "network_connect", "security_event"),
            written.drop(1).map { it.second })
        assertEquals("DNS rows newest-first", listOf(20L, 10L), written.drop(1).take(2).map { it.third })
        assertEquals("the finding row has its record's time", 40L, written.first().third)
        assertTrue(rows().all {
            it.telemetrySource == TelemetrySource.INTRUSION_LOG_IMPORT && it.scanResultId == scanId
        })
    }

    // ---------- findings cap (#342 B3) ----------

    /** The cap applies to ScanResult.findings and the finding rows; criticals survive the cut. */
    @Test
    fun `triggered findings beyond the cap are dropped, keeping highest severity`() = runBlocking {
        val cap = ScanOrchestrator.FINDINGS_PERSIST_CAP
        val criticals = (1L..3L).map { sec(5_000L + it, "critical_cmd") }
        analyzerHandsOver(sec = (1L..(cap + 30).toLong()).map { sec(it) } + criticals)

        val result = f.orchestrator.analyzeIntrusionLog(uri)

        val persisted = f.scans().single()
        assertEquals("ScanResult.findings is capped", cap, persisted.findings.size)
        assertTrue(persisted.findings.all { it.triggered })
        assertEquals(3, persisted.findings.count { it.ruleId == "androdr-il-crit" })
        assertEquals(cap, rows().count { it.source == "intrusion_log_analysis" })
        assertEquals("the card counts past the cap", cap + 33, result.stats.triggeredFindingCount)
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
            assertEquals(1, result.findings.count { it.triggered })
            assertEquals(1, real.timelineDao.getAllForExport().count { it.category == "security_event" })
            assertEquals(1, result.stats.securityEventCount)
            assertEquals(2, result.stats.duplicatesCollapsed)
        }
    }

    /** Interim: re-importing the same log adds no fact ("0 new") and does not stack event rows. */
    @Test
    fun `re-importing the same log shows 0 new facts and does not stack rows`() = runBlocking {
        val zip = IntrusionLogZips.zip("2026-08-22.txt" to listOf(idLess, withId))
        IntrusionLogZips.fixture(engine) { zip }.use { real ->
            real.orchestrator.analyzeIntrusionLog(uri)
            val firstRows = real.timelineDao.getAllForExport().size
            val facts = real.count("SELECT COUNT(*) FROM telemetry_record")
            Thread.sleep(2) // distinct scan ids (epoch ms)

            val again = real.orchestrator.analyzeIntrusionLog(uri)

            assertEquals("the card shows 0 new", 0, again.write!!.newFacts)
            assertEquals(2, again.write!!.alreadyStored)
            assertEquals("no new facts", facts, real.count("SELECT COUNT(*) FROM telemetry_record"))
            assertEquals("rows replaced, not stacked", firstRows, real.timelineDao.getAllForExport().size)
            assertEquals("two observation sets", 4L, real.count("SELECT COUNT(*) FROM scan_record"))
            val latest = real.scans().first().id
            assertTrue(real.timelineDao.getAllForExport().all { it.scanResultId == latest })
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
            live.timelineDao.insertAll(listOf(
                ForensicTimelineEvent(startTimestamp = now - 1_000, source = "intrusion_log",
                    category = "dns_query", description = "imported",
                    telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT, scanResultId = 9L),
                ForensicTimelineEvent(startTimestamp = now - 1_000, source = "app_scanner",
                    category = "package_install", description = "live",
                    telemetrySource = TelemetrySource.LIVE_SCAN, scanResultId = 8L),
            ))
            val events = slot<List<ForensicTimelineEvent>>()
            every { live.correlationEngine.evaluate(any(), capture(events), any(), any()) } returns emptyList()

            live.orchestrator.runFullScan()

            assertEquals(listOf("live"), events.captured.map { it.description })
            assertFalse(events.captured.any { it.telemetrySource == TelemetrySource.INTRUSION_LOG_IMPORT })
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
