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
import com.androdr.sigma.Finding
import io.mockk.coEvery
import io.mockk.coVerifyOrder
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
    private lateinit var orchestrator: ScanOrchestrator

    @Before
    fun setUp() {
        forensicTimelineEventDao = mockk(relaxed = true)
        scanRepository = mockk(relaxed = true)
        intrusionLogAnalyzer = mockk(relaxed = true)

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
            sigmaRuleEngine = mockk(relaxed = true),
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
        matchContext: Map<String, String> = emptyMap()
    ) = Finding(
        ruleId = ruleId, title = ruleId, level = "high",
        triggered = triggered, matchContext = matchContext
    )

    // ---------- replace-on-reimport ----------

    /**
     * A prior import's correlation signals live under
     * `source = "sigma_correlation_engine"` — a source shared with the
     * live-scan and bug-report paths, so it can never be deleted wholesale.
     * They are swept by SCAN ID instead: every row of one import (raw,
     * finding, and signal) carries that import's scanResultId. Without this
     * sweep each re-import stranded one signal cluster whose member ids point
     * at deleted rows, forever.
     */
    @Test
    fun `reimport sweeps every prior import scan id before persisting`() = runTest {
        val uri = mockk<Uri>(relaxed = true)
        coEvery { intrusionLogAnalyzer.analyze(uri) } returns analysis()
        coEvery {
            forensicTimelineEventDao.getDistinctScanIdsBySource("intrusion_log")
        } returns listOf(11L, 22L)

        orchestrator.analyzeIntrusionLog(uri)

        coVerifyOrder {
            forensicTimelineEventDao.getDistinctScanIdsBySource("intrusion_log")
            forensicTimelineEventDao.deleteByScanId(11L)
            forensicTimelineEventDao.deleteByScanId(22L)
            // Belt-and-braces for rows written without a scan id.
            forensicTimelineEventDao.deleteBySource("intrusion_log")
            forensicTimelineEventDao.deleteBySource("intrusion_log_analysis")
            // The new import is written only after the old one is gone.
            scanRepository.saveScanWithCorrelation(any(), any(), any(), any(), any())
        }
    }

    /** No prior import: the sweep degenerates to the two source deletes. */
    @Test
    fun `first import still runs the source deletes`() = runTest {
        val uri = mockk<Uri>(relaxed = true)
        coEvery { intrusionLogAnalyzer.analyze(uri) } returns analysis()
        coEvery {
            forensicTimelineEventDao.getDistinctScanIdsBySource("intrusion_log")
        } returns emptyList()

        orchestrator.analyzeIntrusionLog(uri)

        coVerifyOrder {
            forensicTimelineEventDao.getDistinctScanIdsBySource("intrusion_log")
            forensicTimelineEventDao.deleteBySource("intrusion_log")
            forensicTimelineEventDao.deleteBySource("intrusion_log_analysis")
            scanRepository.saveScanWithCorrelation(any(), any(), any(), any(), any())
        }
    }

    // ---------- persistence caps ----------

    @Test
    fun `dns and connect events are capped newest-first and security events are not`() {
        val dnsTotal = ScanOrchestrator.DNS_PERSIST_CAP + 5
        val netTotal = ScanOrchestrator.CONNECT_PERSIST_CAP + 3
        val secTotal = 25
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
        assertEquals("security events are uncapped", secTotal, secTimes.size)

        // Boundary: newest kept, the events just past the cap dropped.
        assertTrue("newest dns kept", dnsTotal.toLong() in dnsTimes)
        assertEquals("oldest kept dns is exactly at the cap boundary", 6L, dnsTimes.min())
        assertFalse("dns just outside the cap dropped", 5L in dnsTimes)
        assertTrue("newest connect kept", netTotal.toLong() in netTimes)
        assertEquals("oldest kept connect is exactly at the cap boundary", 4L, netTimes.min())
        assertFalse("connect just outside the cap dropped", 3L in netTimes)
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
}
