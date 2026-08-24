package com.androdr.scanner

import android.net.Uri
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.ScanResult
import com.androdr.data.model.SecurityLogEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.ScanRepository
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.sigma.CorrelationRule
import com.androdr.sigma.CorrelationType
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.coVerifyOrder
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Covers the intrusion-log import's two pieces of load-bearing orchestration
 * logic (#342): the replace-on-reimport sweep, and the timeline-row builder
 * that applies the persistence caps.
 *
 * Both are exercised deterministically — no ZIP fixtures, no clock, no DB.
 * The analyzer is mocked, so these tests pin what the ORCHESTRATOR does with
 * an analysis result, independently of how that result was parsed.
 */
class ScanOrchestratorIntrusionLogTest {

    private lateinit var forensicTimelineEventDao: ForensicTimelineEventDao
    private lateinit var scanRepository: ScanRepository
    private lateinit var intrusionLogAnalyzer: IntrusionLogAnalyzer
    private lateinit var sigmaRuleEngine: SigmaRuleEngine
    private lateinit var orchestrator: ScanOrchestrator

    @Before
    fun setUp() {
        forensicTimelineEventDao = mockk(relaxed = true)
        scanRepository = mockk(relaxed = true)
        intrusionLogAnalyzer = mockk(relaxed = true)
        sigmaRuleEngine = mockk(relaxed = true)

        orchestrator = ScanOrchestrator(
            appScanner = mockk(relaxed = true),
            deviceAuditor = mockk(relaxed = true),
            processScanner = mockk(relaxed = true),
            fileArtifactScanner = mockk(relaxed = true),
            accessibilityAuditScanner = mockk(relaxed = true),
            receiverAuditScanner = mockk(relaxed = true),
            appOpsScanner = mockk(relaxed = true),
            usageStatsScanner = mockk(relaxed = true),
            bugReportAnalyzer = mockk(relaxed = true),
            intrusionLogAnalyzer = intrusionLogAnalyzer,
            scanRepository = scanRepository,
            dnsEventDao = mockk(relaxed = true),
            forensicTimelineEventDao = forensicTimelineEventDao,
            installEventEmitter = mockk(relaxed = true),
            deviceAdminGrantEmitter = mockk(relaxed = true),
            sigmaRuleEngine = sigmaRuleEngine,
            sigmaCorrelationEngine = mockk(relaxed = true),
            indicatorResolver = mockk(relaxed = true),
            sigmaRuleFeed = mockk(relaxed = true),
            knownAppResolver = mockk(relaxed = true),
            oemPrefixResolver = mockk(relaxed = true),
            brandImpersonationResolver = mockk(relaxed = true),
            context = mockk(relaxed = true)
        )
    }

    // ---------- fixtures ----------

    private fun stats() = IntrusionLogStats(0, 0, 0, 0, 0, null, null)

    private fun analysis(
        findings: List<Finding> = emptyList(),
        dns: List<ImportedDnsEvent> = emptyList(),
        net: List<NetworkTelemetry> = emptyList(),
        sec: List<SecurityLogEvent> = emptyList()
    ) = IntrusionLogAnalysisResult(findings, dns, net, sec, stats())

    private fun scanResult(id: Long = 100L) = ScanResult(
        id = id,
        timestamp = id,
        findings = emptyList(),
        bugReportFindings = emptyList(),
        riskySideloadCount = 0,
        knownMalwareCount = 0
    )

    private fun dns(ts: Long) = ImportedDnsEvent(
        event = DnsEvent(
            timestamp = ts, domain = "d$ts.example.com", appUid = 10,
            appName = "com.a", isBlocked = false, reason = null
        ),
        resolvedIps = emptyList()
    )

    private fun net(ts: Long) = NetworkTelemetry(
        destinationIp = "10.0.0.1", destinationPort = 443, protocol = null,
        appUid = -1, appName = "com.b", timestamp = ts,
        source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = 0L
    )

    private fun sec(ts: Long) = SecurityLogEvent(
        timestamp = ts, tag = 210002, tagName = "adb_shell_cmd",
        securityData = listOf("id"), source = TelemetrySource.INTRUSION_LOG_IMPORT,
        capturedAt = 0L
    )

    private fun finding(
        ruleId: String,
        triggered: Boolean = true,
        level: String = "high",
        matchContext: Map<String, String> = emptyMap()
    ) = Finding(
        ruleId = ruleId, title = ruleId, level = level,
        triggered = triggered, matchContext = matchContext
    )

    /**
     * Stubs the (mocked) repository's save to invoke the caller-supplied
     * `preDelete` lambda, the way the real transaction does — so tests can
     * observe the replace-on-reimport sweep that now runs INSIDE the save
     * (#342 B1). preDelete is positional arg 4; correlator is arg 5.
     */
    private fun saveInvokesPreDelete() {
        coEvery {
            scanRepository.saveScanWithCorrelation(any(), any(), any(), any(), any(), any())
        } coAnswers {
            arg<(suspend () -> Unit)?>(4)?.invoke()
        }
    }

    // ---------- replace-on-reimport (now atomic with the save, #342 B1) ----------

    /**
     * A prior import's correlation signals live under
     * `source = "sigma_correlation_engine"` — a source shared with the
     * live-scan and bug-report paths, so it can never be deleted wholesale.
     * They are swept by SCAN ID instead: every row of one import (raw,
     * finding, and signal) carries that import's scanResultId. Without this
     * sweep each re-import stranded one signal cluster whose member ids point
     * at deleted rows, forever.
     *
     * B1: the sweep now runs via `preDelete` INSIDE the save transaction. Here
     * the mocked save invokes that lambda (as the real transaction would), so
     * we can still assert the sweep order.
     */
    @Test
    fun `reimport sweeps every prior import scan id via preDelete inside the save`() = runTest {
        val uri = mockk<Uri>(relaxed = true)
        coEvery { intrusionLogAnalyzer.analyze(uri) } returns analysis()
        coEvery {
            forensicTimelineEventDao.getDistinctScanIdsBySource("intrusion_log")
        } returns listOf(11L, 22L)
        saveInvokesPreDelete()

        orchestrator.analyzeIntrusionLog(uri)

        coVerifyOrder {
            forensicTimelineEventDao.getDistinctScanIdsBySource("intrusion_log")
            forensicTimelineEventDao.deleteByScanId(11L)
            forensicTimelineEventDao.deleteByScanId(22L)
            // Belt-and-braces for rows written without a scan id.
            forensicTimelineEventDao.deleteBySource("intrusion_log")
            forensicTimelineEventDao.deleteBySource("intrusion_log_analysis")
        }
    }

    /** No prior import: the sweep degenerates to the two source deletes. */
    @Test
    fun `first import still runs the source deletes via preDelete`() = runTest {
        val uri = mockk<Uri>(relaxed = true)
        coEvery { intrusionLogAnalyzer.analyze(uri) } returns analysis()
        coEvery {
            forensicTimelineEventDao.getDistinctScanIdsBySource("intrusion_log")
        } returns emptyList()
        saveInvokesPreDelete()

        orchestrator.analyzeIntrusionLog(uri)

        coVerifyOrder {
            forensicTimelineEventDao.getDistinctScanIdsBySource("intrusion_log")
            forensicTimelineEventDao.deleteBySource("intrusion_log")
            forensicTimelineEventDao.deleteBySource("intrusion_log_analysis")
        }
    }

    /**
     * #342 B1 (merge-blocking): if the save fails, the prior import must NOT be
     * deleted (the sweep is inside the rolled-back transaction, so it never runs
     * when the mocked save throws before invoking preDelete), and the failure
     * must be SURFACED — not swallowed into a false success. The original code
     * deleted first, outside the save, and swallowed the failure with
     * `runCatching {}.onFailure { Log.e }`, so both assertions below fail on it.
     */
    @Test
    fun `a failed save deletes nothing and surfaces the failure`() = runTest {
        val uri = mockk<Uri>(relaxed = true)
        coEvery { intrusionLogAnalyzer.analyze(uri) } returns analysis()
        coEvery {
            forensicTimelineEventDao.getDistinctScanIdsBySource("intrusion_log")
        } returns listOf(11L)
        // The save throws WITHOUT invoking preDelete — mirroring a transaction
        // that rolls back before/while committing.
        coEvery {
            scanRepository.saveScanWithCorrelation(any(), any(), any(), any(), any(), any())
        } throws RuntimeException("db write failed")

        var thrown: Throwable? = null
        try {
            orchestrator.analyzeIntrusionLog(uri)
        } catch (e: Throwable) {
            thrown = e
        }

        assertNotNull("a failed persist must be surfaced, not swallowed as success", thrown)
        assertTrue(
            "failure must be the honest IntrusionLogPersistException: $thrown",
            thrown is ScanOrchestrator.IntrusionLogPersistException
        )
        coVerify(exactly = 0) { forensicTimelineEventDao.deleteByScanId(any()) }
        coVerify(exactly = 0) { forensicTimelineEventDao.deleteBySource(any()) }
    }

    /** The import's save is wired with a non-null preDelete (the sweep). */
    @Test
    fun `analyzeIntrusionLog passes a preDelete sweep to the save`() = runTest {
        val uri = mockk<Uri>(relaxed = true)
        coEvery { intrusionLogAnalyzer.analyze(uri) } returns analysis()
        val preDelete = slot<suspend () -> Unit>()
        coEvery {
            scanRepository.saveScanWithCorrelation(
                any(), any(), any(), any(), capture(preDelete), any()
            )
        } returns Unit

        orchestrator.analyzeIntrusionLog(uri)

        assertTrue("save must receive a non-null preDelete sweep", preDelete.isCaptured)
    }

    // ---------- persistence caps ----------

    @Test
    fun `dns and connect events are capped newest-first and security stays under its cap`() {
        val dnsTotal = ScanOrchestrator.DNS_PERSIST_CAP + 5
        val netTotal = ScanOrchestrator.CONNECT_PERSIST_CAP + 3
        val secTotal = 25 // well below SECURITY_PERSIST_CAP, so kept in full
        // Oldest-first input, so a cap that ignored ordering would keep the
        // WRONG (oldest) events and fail the boundary assertions below.
        val result = analysis(
            dns = (1L..dnsTotal.toLong()).map { dns(it) },
            net = (1L..netTotal.toLong()).map { net(it) },
            sec = (1L..secTotal.toLong()).map { sec(it) }
        )

        val rows = orchestrator.buildIntrusionLogTimelineEvents(result, scanResult())

        val dnsTimes = rows.filter { it.category == "dns_query" }.map { it.startTimestamp }
        val netTimes = rows.filter { it.category == "network_connect" }.map { it.startTimestamp }
        val secTimes = rows.filter { it.category == "security_event" }.map { it.startTimestamp }

        assertEquals(ScanOrchestrator.DNS_PERSIST_CAP, dnsTimes.size)
        assertEquals(ScanOrchestrator.CONNECT_PERSIST_CAP, netTimes.size)
        assertEquals("security below the cap is kept in full", secTotal, secTimes.size)

        // Boundary: newest kept, the events just past the cap dropped.
        assertTrue("newest dns kept", dnsTotal.toLong() in dnsTimes)
        assertEquals("oldest kept dns is exactly at the cap boundary", 6L, dnsTimes.min())
        assertFalse("dns just outside the cap dropped", 5L in dnsTimes)
        assertTrue("newest connect kept", netTotal.toLong() in netTimes)
        assertEquals("oldest kept connect is exactly at the cap boundary", 4L, netTimes.min())
        assertFalse("connect just outside the cap dropped", 3L in netTimes)
    }

    /**
     * #342 B4 / security L1: security events are no longer persisted uncapped.
     * A crafted export of millions of `security_event` lines would otherwise
     * persist millions of rows surviving the 30-day retention. They are kept
     * newest-first up to [ScanOrchestrator.SECURITY_PERSIST_CAP].
     */
    @Test
    fun `security events beyond the cap are dropped newest-first`() {
        val secTotal = ScanOrchestrator.SECURITY_PERSIST_CAP + 7
        // Oldest-first input, so an order-blind cap keeps the wrong events.
        val result = analysis(sec = (1L..secTotal.toLong()).map { sec(it) })

        val rows = orchestrator.buildIntrusionLogTimelineEvents(result, scanResult())
        val secTimes = rows.filter { it.category == "security_event" }.map { it.startTimestamp }

        assertEquals(ScanOrchestrator.SECURITY_PERSIST_CAP, secTimes.size)
        assertTrue("newest security kept", secTotal.toLong() in secTimes)
        assertEquals("oldest kept security is exactly at the cap boundary", 8L, secTimes.min())
        assertFalse("security just outside the cap dropped", 7L in secTimes)
    }

    // ---------- findings persistence cap (#342 B3) ----------

    /**
     * #342 B3 (SEVERE): one Finding is emitted per (record × matching rule) over
     * the uncapped stream, so a beaconing domain can produce thousands. Persisting
     * them all bloats the ScanResult JSON column past Room's CursorWindow and
     * bricks history app-wide. Only [ScanOrchestrator.FINDINGS_PERSIST_CAP] rows
     * are persisted, keeping the highest-severity ones.
     */
    @Test
    fun `triggered findings beyond the cap are dropped, keeping highest severity`() {
        val cap = ScanOrchestrator.FINDINGS_PERSIST_CAP
        val criticalIds = listOf("crit-1", "crit-2", "crit-3")
        // cap+50 lows plus 3 criticals — the criticals must survive the cut and
        // the total must be exactly the cap.
        val findings = buildList {
            repeat(cap + 50) { add(finding("low-$it", level = "low")) }
            criticalIds.forEach { add(finding(it, level = "critical")) }
        }
        val result = analysis(findings = findings)

        val rows = orchestrator.buildIntrusionLogTimelineEvents(result, scanResult())
        val findingRows = rows.filter { it.source == "intrusion_log_analysis" }

        assertEquals("finding rows are capped", cap, findingRows.size)
        val keptIds = findingRows.map { it.ruleId }.toSet()
        assertTrue("all critical findings survive the cut", keptIds.containsAll(criticalIds))
        assertTrue("some low findings were dropped", findingRows.size < findings.size)
    }

    /** The SAME cap applies to what lands in ScanResult.findings (the JSON column). */
    @Test
    fun `persisted ScanResult keeps only the capped triggered findings`() = runTest {
        val cap = ScanOrchestrator.FINDINGS_PERSIST_CAP
        val uri = mockk<Uri>(relaxed = true)
        val findings = buildList {
            repeat(cap + 30) { add(finding("t-$it", level = "high")) }
            add(finding("untriggered", triggered = false))
        }
        coEvery { intrusionLogAnalyzer.analyze(uri) } returns analysis(findings = findings)
        val scan = slot<ScanResult>()
        coEvery {
            scanRepository.saveScanWithCorrelation(capture(scan), any(), any(), any(), any(), any())
        } returns Unit

        orchestrator.analyzeIntrusionLog(uri)

        assertEquals("ScanResult.findings is capped", cap, scan.captured.findings.size)
        assertTrue(
            "only triggered findings are persisted",
            scan.captured.findings.all { it.triggered }
        )
    }

    /**
     * #356: the persisted scan must carry the import's identity, otherwise
     * History renders an intrusion-log import exactly like a live device scan
     * and the user cannot tell which device state they are looking at.
     */
    @Test
    fun `persisted ScanResult is stamped INTRUSION_LOG_IMPORT`() = runTest {
        val uri = mockk<Uri>(relaxed = true)
        coEvery { intrusionLogAnalyzer.analyze(uri) } returns analysis()
        val scan = slot<ScanResult>()
        coEvery {
            scanRepository.saveScanWithCorrelation(capture(scan), any(), any(), any(), any(), any())
        } returns Unit

        orchestrator.analyzeIntrusionLog(uri)

        assertEquals(TelemetrySource.INTRUSION_LOG_IMPORT, scan.captured.source)
    }

    // ---------- composition ----------

    @Test
    fun `rows are findings then dns then connect then security with import sources`() {
        val result = analysis(
            findings = listOf(finding("androdr-1"), finding("androdr-2", triggered = false)),
            dns = listOf(dns(10L), dns(20L)),
            net = listOf(net(30L)),
            sec = listOf(sec(40L))
        )

        val rows = orchestrator.buildIntrusionLogTimelineEvents(result, scanResult(id = 100L))

        assertEquals("untriggered findings produce no row", 5, rows.size)
        assertEquals("intrusion_log_analysis", rows[0].source)
        assertEquals("androdr-1", rows[0].ruleId)
        assertEquals(listOf("intrusion_log", "intrusion_log", "intrusion_log", "intrusion_log"),
            rows.drop(1).map { it.source })
        assertEquals(
            listOf("dns_query", "dns_query", "network_connect", "security_event"),
            rows.drop(1).map { it.category }
        )
        // DNS segment is newest-first (the cap's ordering, applied always).
        assertEquals(listOf(20L, 10L), rows.drop(1).take(2).map { it.startTimestamp })
        assertTrue(
            "every row is stamped INTRUSION_LOG_IMPORT",
            rows.all { it.telemetrySource == TelemetrySource.INTRUSION_LOG_IMPORT }
        )
        assertTrue("every row is tied to the import's scan", rows.all { it.scanResultId == 100L })
    }

    @Test
    fun `finding rows inherit the matched record timestamp and fall back to zero`() {
        val result = analysis(
            findings = listOf(
                finding("androdr-ts", matchContext = mapOf("timestamp" to "1700000000000")),
                finding("androdr-none"),
                finding("androdr-zero", matchContext = mapOf("timestamp" to "0")),
                finding("androdr-junk", matchContext = mapOf("timestamp" to "not-a-number"))
            )
        )

        val rows = orchestrator.buildIntrusionLogTimelineEvents(result, scanResult())

        assertEquals(1_700_000_000_000L, rows.first { it.ruleId == "androdr-ts" }.startTimestamp)
        assertEquals(0L, rows.first { it.ruleId == "androdr-none" }.startTimestamp)
        assertEquals(0L, rows.first { it.ruleId == "androdr-zero" }.startTimestamp)
        assertEquals(0L, rows.first { it.ruleId == "androdr-junk" }.startTimestamp)
    }

    // ---------- live-scan correlation lookback excludes imports (#342 B2) ----------

    /**
     * #342 B2: a LIVE scan's correlation lookback must NOT pull imported
     * intrusion-log rows. They carry their own historical event time, so a plain
     * `getEventsSince` time-window query sweeps them in; any resulting signal is
     * stamped with the LIVE scan's id, which the intrusion sweep can never reach
     * (an orphan signal accumulating per live scan). The live path must use the
     * scoped query that excludes INTRUSION_LOG_IMPORT, and must NOT call the
     * unscoped [ForensicTimelineEventDao.getEventsSince]. Reverting the call site
     * to `getEventsSince` fails this test.
     */
    @Test
    fun `live scan lookback uses the query that excludes imported rows`() = runTest {
        coEvery { sigmaRuleEngine.getCorrelationRules() } returns listOf(
            CorrelationRule(
                id = "corr-1", title = "t", type = CorrelationType.TEMPORAL,
                referencedRuleIds = listOf("a", "b"), timespanMs = 3_600_000L,
                groupBy = emptyList(), minEvents = 1, severity = "high", displayLabel = "l"
            )
        )

        orchestrator.runFullScan()

        coVerify(exactly = 1) {
            forensicTimelineEventDao.getEventsSinceExcludingTelemetrySource(
                any(), TelemetrySource.INTRUSION_LOG_IMPORT
            )
        }
        coVerify(exactly = 0) { forensicTimelineEventDao.getEventsSince(any()) }
    }
}
