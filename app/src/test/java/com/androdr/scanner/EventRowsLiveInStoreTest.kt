package com.androdr.scanner

import android.net.Uri
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.UsageEvent
import com.androdr.sigma.CorrelationRule
import com.androdr.sigma.CorrelationType
import com.androdr.sigma.IntrusionLogRecordBuilders
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * C3 (spec §5.3, §5.6): event records live only in the store. Imports and live scans write no
 * event rows to `forensic_timeline` — only finding rows, signals and the live detected changes —
 * while every record is an observation; re-importing a log stacks observations, not facts or rows.
 */
@RunWith(RobolectricTestRunner::class)
class EventRowsLiveInStoreTest {
    private val engine = IntrusionLogZips.engine(
        IntrusionLogZips.rule("androdr-c3-sec", "security_log", "tag_name", "adb_shell_cmd", "high"),
    )
    private val f = OrchestratorFixture(engine = engine)
    private val uri = mockk<Uri>(relaxed = true)

    @After fun tearDown() = f.close()

    private fun dns(i: Int) = ImportedDnsEvent(
        event = DnsEvent(timestamp = 1_000L + i, domain = "d$i.example.com", appUid = 10, appName = "com.a",
            isBlocked = false, reason = null),
        resolvedIps = emptyList(),
    )

    private fun net(i: Int) = NetworkTelemetry(
        destinationIp = "10.0.0.${i % 250}", destinationPort = 443 + i, protocol = null, appUid = -1,
        appName = "com.b", timestamp = 2_000L + i, source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
    )

    private fun sec(i: Int, tag: String) = SecurityLogEvent(
        timestamp = 3_000L + i, tag = 210002, tagName = tag, securityData = listOf("$i"),
        source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L,
    )

    /** Every row as (source, kind, ruleId), visible or not. */
    private fun rows(g: OrchestratorFixture = f): List<Triple<String, String, String>> =
        g.db.openHelper.readableDatabase.query("SELECT source, kind, ruleId FROM forensic_timeline ORDER BY id")
            .use { c ->
                generateSequence {
                    if (c.moveToNext()) Triple(c.getString(0), c.getString(1), c.getString(2)) else null
                }.toList()
            }

    @Test
    fun `a 7,000-event intrusion log writes only finding rows and signals, and 7,000 observations`() =
        runBlocking {
            val dns = (0 until 3_000).map(::dns)
            val net = (0 until 2_000).map(::net)
            val sec = (0 until 2_000).map { sec(it, if (it % 100 == 0) "adb_shell_cmd" else "other") }
            coEvery { f.intrusionLogAnalyzer.analyze(any(), any()) } coAnswers {
                val chunks = secondArg<IntrusionLogChunks>()
                dns.chunked(ChunkedScanWriter.CHUNK_SIZE).forEachIndexed { c, part ->
                    chunks.dns(part, IntrusionLogRecordBuilders.importedDns(part, part.indices.map { "dns ${c}_$it" }))
                }
                net.chunked(ChunkedScanWriter.CHUNK_SIZE).forEachIndexed { c, part ->
                    chunks.connect(part, IntrusionLogRecordBuilders.network(part, part.indices.map { "net ${c}_$it" }))
                }
                sec.chunked(ChunkedScanWriter.CHUNK_SIZE).forEachIndexed { c, part ->
                    chunks.security(part,
                        IntrusionLogRecordBuilders.securityLog(part, part.indices.map { "sec ${c}_$it" }))
                }
                IntrusionLogScan(IntrusionLogStats(dns.size, net.size, sec.size, 0, 0, null, null), emptyList())
            }

            f.orchestrator.analyzeIntrusionLog(uri)

            val scanId = f.scans().single().id
            assertEquals("every record is an observation", 7_000L,
                f.count("SELECT COUNT(*) FROM scan_record WHERE scanId = $scanId"))
            val written = rows()
            assertEquals("one finding row per triggered finding", 20, written.size)
            assertTrue("only finding rows and signals: $written",
                written.all { (_, kind, ruleId) -> ruleId.isNotEmpty() || kind == "signal" })
            assertEquals(0L, f.count("SELECT COUNT(*) FROM forensic_timeline WHERE source = 'intrusion_log'"))
        }

    @Test
    fun `a live scan writes no usage_stats row and stores every usage event`() = runBlocking {
        val t = System.currentTimeMillis()
        coEvery { f.usageStatsScanner.collectEvents(any(), any()) } returns UsageCollection.Ok(listOf(
            UsageEvent(t - 60_000L, "com.a", "A", "app_foreground", TelemetrySource.LIVE_SCAN, t),
            UsageEvent(t - 30_000L, "com.a", "A", "app_background", TelemetrySource.LIVE_SCAN, t),
        ))

        f.orchestrator.runFullScan()

        assertEquals(0L, f.count("SELECT COUNT(*) FROM forensic_timeline WHERE source = 'usage_stats'"))
        assertEquals("no event row of any kind", 0L, f.count("SELECT COUNT(*) FROM forensic_timeline"))
        assertEquals(2L, f.count("SELECT COUNT(*) FROM scan_record WHERE service = 'usage_stats'"))
    }

    @Test
    fun `a live scan still writes its detected changes`() = runBlocking {
        coEvery { f.installEventEmitter.emitNew(any(), any()) } answers {
            listOf(com.androdr.data.model.ForensicTimelineEvent(startTimestamp = 5L, source = "app_scanner",
                category = "package_install", description = "Package installed: X", packageName = "com.x",
                scanResultId = firstArg()))
        }

        f.orchestrator.runFullScan()

        assertEquals(listOf("app_scanner"), rows().map { it.first })
    }

    private val idLess = """{"security_event":{"event_time":1787400345600,"tag":210002,"data":["ls"]}}"""
    private val withId =
        """{"security_event":{"event_id":4,"event_time":1787400345700,"tag":210002,"data":["id"]}}"""

    /** Replace-on-reimport is gone (spec §5.2): both imports keep their finding rows; no event rows. */
    @Test
    fun `re-importing a log gives one set of facts, two observation sets and no event rows`() = runBlocking {
        val zip = IntrusionLogZips.zip("2026-08-22.txt" to listOf(idLess, withId))
        IntrusionLogZips.fixture(engine) { zip }.use { real ->
            real.orchestrator.analyzeIntrusionLog(uri)
            val facts = real.count("SELECT COUNT(*) FROM telemetry_record")
            val firstRows = rows(real)
            Thread.sleep(2) // distinct scan ids (epoch ms)

            val again = real.orchestrator.analyzeIntrusionLog(uri)

            assertEquals(2L, facts)
            assertEquals("no new facts", facts, real.count("SELECT COUNT(*) FROM telemetry_record"))
            assertEquals(0, again.write!!.newFacts)
            assertEquals("two observation sets", 4L, real.count("SELECT COUNT(*) FROM scan_record"))
            assertEquals(2L, real.count("SELECT COUNT(DISTINCT scanId) FROM scan_record"))
            assertTrue("the first import wrote its finding row", firstRows.isNotEmpty())
            val all = rows(real)
            assertTrue("finding rows only: $all", all.all { it.third.isNotEmpty() || it.second == "signal" })
            assertEquals("each import keeps its own finding rows", 2 * firstRows.size, all.size)
        }
    }

    /** The bug-report modules' hand-built rows are retired (spec §5.3): only finding rows remain. */
    @Test
    fun `a bug-report import writes no module rows`() = runBlocking {
        OrchestratorFixture(engine = IntrusionLogZips.engine(), bugReportAnalyzer = BugReportFixtures.analyzer())
            .use { g ->
                g.orchestrator.analyzeBugReport(uri)
                assertTrue("records stored", g.count("SELECT COUNT(*) FROM scan_record") > 0L)
                assertEquals("no rule fired, so no row at all: ${rows(g)}", 0L,
                    g.count("SELECT COUNT(*) FROM forensic_timeline"))
            }
    }

    /**
     * C1 m4 carried: a usage event already observed by an earlier live scan is counted once across
     * consecutive scans — the re-read event is the same fact and gets no second observation, so it
     * reaches correlation once, through the lookback (no usage rows, no sweep).
     */
    @Test
    fun `a usage event re-read by the next scan is one correlation atom`() = runBlocking {
        val correlation = mockk<com.androdr.sigma.SigmaCorrelationEngine>(relaxed = true)
        OrchestratorFixture(correlationEngine = correlation).use { g ->
            io.mockk.every { g.engine.atomCategories() } returns mapOf("a" to "app_foreground")
            io.mockk.every { g.engine.getCorrelationRules() } returns listOf(CorrelationRule(id = "corr-u",
                title = "t", type = CorrelationType.EVENT_COUNT, referencedRuleIds = listOf("a"),
                timespanMs = 3_600_000L, groupBy = emptyList(), minEvents = 2, severity = "high", displayLabel = "l"))
            val usageTime = System.currentTimeMillis() - 60_000L
            coEvery { g.usageStatsScanner.collectEvents(any(), any()) } returns UsageCollection.Ok(listOf(
                UsageEvent(usageTime, "com.a", "A", "app_foreground", TelemetrySource.LIVE_SCAN, 1L)))
            val inputs = mutableListOf<List<com.androdr.sigma.TimelineAtom>>()
            io.mockk.every { correlation.evaluate(any(), any(), any(), any(), any()) } answers {
                inputs += secondArg<List<com.androdr.sigma.TimelineAtom>>()
                com.androdr.sigma.CorrelationResult.NONE
            }

            g.orchestrator.runFullScan()
            Thread.sleep(2)
            g.orchestrator.runFullScan()

            assertEquals(2, inputs.size)
            assertEquals("scan 2 binds the re-read event once", 1,
                inputs[1].count { it.category == "app_foreground" && it.timestamp == usageTime })
            assertTrue("as a fact atom", inputs[1].all { it.ref is com.androdr.sigma.Fact })
            assertEquals("one fact, one observation", 1L,
                g.count("SELECT COUNT(*) FROM scan_record WHERE service = 'usage_stats'"))
        }
    }
}
