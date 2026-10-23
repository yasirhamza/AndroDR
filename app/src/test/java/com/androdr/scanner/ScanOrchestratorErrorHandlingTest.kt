package com.androdr.scanner

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanWithFindings
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.UNREGISTERED_IOC_LOOKUP
import com.androdr.network.DnsVpnService
import com.androdr.sigma.SigmaRuleFeed
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Error-handling tests for [ScanOrchestrator].
 *
 * The critical behavior under test is that **scanner exceptions must not
 * silently disappear**. The previous implementation used
 * `runCatching { ... }.getOrDefault(emptyList())` in every scanner call site,
 * which turned any per-scanner crash into an empty telemetry list with no
 * log trail — a direct detection-evasion hazard because a malware sample
 * that crashes a scanner would yield "clean" results indistinguishable
 * from an actually-clean device.
 *
 * These tests inject deliberate exceptions from mocked scanners and verify:
 *  1. The failure is recorded in [ScanResult.scannerErrors].
 *  2. Other scanners still run and their results appear in findings.
 *  3. [CancellationException] is propagated, not recorded as a failure.
 *  4. The scan progress returns to [ScanProgress.Idle] on both the
 *     success path and the exception path.
 *
 * Mutation-tested: reverting `LiveScanCollector.trackedAsync` to the old
 * `runCatching { ... }.getOrDefault(...)` pattern causes `scannerErrors`
 * to be empty and both of the first two tests to fail.
 *
 * The second group (`capability skip …`) covers the OTHER kind of entry that
 * lands in the same list: rules this binary cannot evaluate (#136 R1). Those
 * tests exist because the whole fail-closed feature hangs off one call —
 * `recordRuleCapabilitySkips(...)` — and deleting that call left every other
 * test in the suite green: the evaluator-level tests prove skipping happens,
 * the ReportFormatter tests prove a skip entry renders, but nothing proved the
 * orchestrator actually writes one. They share this harness deliberately rather
 * than standing up a third ~20-mock orchestrator fixture.
 */
@RunWith(RobolectricTestRunner::class)
class ScanOrchestratorErrorHandlingTest {

    // The writer session runs on a real in-memory database; everything else is a relaxed mock.
    private val f = OrchestratorFixture()
    private val appScanner = f.appScanner
    private val deviceAuditor = f.deviceAuditor
    private val processScanner = f.processScanner
    private val fileArtifactScanner = f.fileArtifactScanner
    private val accessibilityAuditScanner = f.accessibilityAuditScanner
    private val receiverAuditScanner = f.receiverAuditScanner
    private val appOpsScanner = f.appOpsScanner
    private val usageStatsScanner = f.usageStatsScanner
    private val bugReportAnalyzer = f.bugReportAnalyzer
    private val dnsEventDao = f.dnsEventDao
    private val sigmaRuleEngine = f.engine
    private val indicatorResolver = f.indicatorResolver
    private val orchestrator get() = f.orchestrator

    @Before
    fun setUp() {
        // Happy defaults: every scanner returns an empty list. Individual tests override these to throw.
        coEvery { appScanner.collectTelemetry() } returns emptyList()
        coEvery { deviceAuditor.collectTelemetry() } returns emptyList()
        coEvery { processScanner.collectTelemetry() } returns emptyList()
        coEvery { fileArtifactScanner.collectTelemetry() } returns emptyList()
        coEvery { accessibilityAuditScanner.collectTelemetry() } returns emptyList()
        coEvery { receiverAuditScanner.collectTelemetry() } returns emptyList()
        coEvery { appOpsScanner.collectTelemetry() } returns emptyList()
        coEvery { usageStatsScanner.collectEvents(any(), any()) } returns UsageCollection.Ok(emptyList())
        coEvery { f.sigmaRuleFeed.fetch() } returns emptyList()
        every { sigmaRuleEngine.evaluateRecords(any(), any(), any()) } returns emptyList()
        every { sigmaRuleEngine.getRules() } returns emptyList()
    }

    @After
    fun tearDown() = f.close()

    @Test
    fun `scanner exception is recorded in scannerErrors instead of being swallowed`() = runBlocking {
        val boom = IllegalStateException("boom — simulated scanner crash")
        coEvery { appScanner.collectTelemetry() } throws boom

        val result: ScanWithFindings = orchestrator.runFullScan()

        assertTrue(
            "scan with a failing scanner must be marked as partial",
            result.isPartialScan
        )
        assertEquals(1, result.scannerErrors.size)
        val failure = result.scannerErrors.single()
        assertEquals("appScanner", failure.scanner)
        assertEquals("IllegalStateException", failure.exception)
        assertEquals("boom — simulated scanner crash", failure.message)
    }

    @Test
    fun `a failed DNS snapshot read is recorded as dnsSnapshot and the scan completes`() = runBlocking {
        coEvery { dnsEventDao.maxId() } throws IllegalStateException("database is locked")

        val result: ScanWithFindings = orchestrator.runFullScan()

        val failure = result.scannerErrors.single { it.scanner == "dnsSnapshot" }
        assertEquals("IllegalStateException", failure.exception)
        assertEquals("database is locked", failure.message)
        assertTrue("DNS rules did not run: the scan is partial", result.isPartialScan)
    }

    @Test
    fun `cancellation during the DNS snapshot read propagates`() = runBlocking {
        coEvery { dnsEventDao.maxId() } throws CancellationException("user cancelled")
        var caught: Throwable? = null
        try { orchestrator.runFullScan() } catch (e: CancellationException) { caught = e }
        assertNotNull(caught)
    }

    @Test
    fun `one scanner failing does not cascade — other scanners still run and get recorded`() = runBlocking {
        coEvery { fileArtifactScanner.collectTelemetry() } throws RuntimeException("file scanner dead")

        val result: ScanWithFindings = orchestrator.runFullScan()

        // The specific scanner that failed is recorded.
        assertTrue(result.isPartialScan)
        assertEquals(1, result.scannerErrors.size)
        assertEquals("fileArtifactScanner", result.scannerErrors.single().scanner)

        // Verify the other seven scanners were still invoked despite the failure.
        io.mockk.coVerify(exactly = 1) { appScanner.collectTelemetry() }
        io.mockk.coVerify(exactly = 1) { deviceAuditor.collectTelemetry() }
        io.mockk.coVerify(exactly = 1) { processScanner.collectTelemetry() }
        io.mockk.coVerify(exactly = 1) { accessibilityAuditScanner.collectTelemetry() }
        io.mockk.coVerify(exactly = 1) { receiverAuditScanner.collectTelemetry() }
        io.mockk.coVerify(exactly = 1) { appOpsScanner.collectTelemetry() }
        io.mockk.coVerify(exactly = 1) { usageStatsScanner.collectEvents(any(), any()) }
    }

    @Test
    fun `multiple scanners can fail independently and all failures are recorded`() = runBlocking {
        coEvery { appScanner.collectTelemetry() } throws RuntimeException("a")
        coEvery { deviceAuditor.collectTelemetry() } throws IllegalStateException("b")
        coEvery { processScanner.collectTelemetry() } throws NullPointerException("c")

        val result: ScanWithFindings = orchestrator.runFullScan()

        assertEquals(3, result.scannerErrors.size)
        val scannerNames = result.scannerErrors.map { it.scanner }.toSet()
        assertTrue(scannerNames.contains("appScanner"))
        assertTrue(scannerNames.contains("deviceAuditor"))
        assertTrue(scannerNames.contains("processScanner"))
    }

    @Test
    fun `CancellationException propagates and is not swallowed as a scanner failure`() = runBlocking {
        coEvery { appScanner.collectTelemetry() } throws CancellationException("user cancelled")

        var caught: Throwable? = null
        try {
            orchestrator.runFullScan()
        } catch (e: CancellationException) {
            caught = e
        }

        assertNotNull(
            "CancellationException must propagate out of runFullScan, not be swallowed",
            caught
        )
    }

    @Test
    fun `successful scan has empty scannerErrors and is not marked partial`() = runBlocking {
        val result: ScanWithFindings = orchestrator.runFullScan()

        assertFalse(result.isPartialScan)
        assertTrue(result.scannerErrors.isEmpty())
    }

    @Test
    fun `scanProgress returns to Idle after a successful scan`() = runBlocking {
        orchestrator.runFullScan()
        assertEquals(ScanProgress.Idle, orchestrator.scanProgress.value)
    }

    @Test
    fun `scanProgress returns to Idle even when a scanner throws`() = runBlocking {
        coEvery { appScanner.collectTelemetry() } throws RuntimeException("boom")
        orchestrator.runFullScan()
        assertEquals(ScanProgress.Idle, orchestrator.scanProgress.value)
    }

    // ---- Capability skips (#136 R1) ------------------------------------------

    /** The ScanResult the session persisted (the only completed scan). */
    private suspend fun capturePersistedScan(): ScanResult = f.scans().single()

    @Test
    fun `capability skip is recorded on the persisted scan and does not mark it partial`() = runBlocking {
        every { sigmaRuleEngine.unevaluableRules() } returns
            mapOf("androdr-010" to "trusted_installer_db")

        val result = orchestrator.runFullScan()

        val skip = result.scannerErrors.single()
        assertEquals("ruleCapability", skip.scanner)
        assertEquals(UNREGISTERED_IOC_LOOKUP, skip.exception)
        assertEquals("androdr-010", skip.ruleId)
        assertTrue(
            "message must name the rule and the unresolved lookup: ${skip.message}",
            skip.message!!.contains("androdr-010") && skip.message!!.contains("trusted_installer_db")
        )
        // A skip is accepted under-detection, NOT a failed scan: the
        // partial-scan banner must stay down.
        assertFalse(result.isPartialScan)
        assertEquals(0, result.realFailureCount)

        // And it must survive into the row the report/diff read from.
        assertEquals(result.scannerErrors, capturePersistedScan().scannerErrors)
    }

    @Test
    fun `capability skips coexist with a real scanner failure without inflating its count`() = runBlocking {
        every { sigmaRuleEngine.unevaluableRules() } returns
            mapOf("androdr-010" to "trusted_installer_db", "androdr-017" to "known_good_app_db")
        coEvery { appScanner.collectTelemetry() } throws RuntimeException("boom")

        val result = orchestrator.runFullScan()

        assertEquals(3, result.scannerErrors.size)
        assertTrue(result.isPartialScan)
        assertEquals("the banner counts only real failures", 1, result.realFailureCount)
        assertEquals(
            setOf("androdr-010", "androdr-017"),
            result.scannerErrors.filter { it.exception == UNREGISTERED_IOC_LOOKUP }
                .mapNotNull { it.ruleId }.toSet()
        )
    }

    // -- #288: a remote rule this build could not read is a named gap, not a log line --

    @Test
    fun `a rejected remote rule with no built-in copy is declared not evaluated, by id`() = runBlocking {
        every { sigmaRuleEngine.rejectedRemoteRules() } returns listOf(
            SigmaRuleFeed.RejectedRuleFile("new_rule.yml", "androdr-950", "missing display.category"),
        )

        val skip = orchestrator.runFullScan().scannerErrors.single()

        assertEquals(NotEvaluatedReason.MISSING_CAPABILITY.sentinel, skip.exception)
        assertEquals("History must not call this rule resolved", "androdr-950", skip.ruleId)
        assertTrue(skip.message!!.contains("androdr-950"))
        assertFalse("not a failed scanner", orchestrator.runFullScan().isPartialScan)
    }

    @Test
    fun `a rejected update to a rule that still runs says an earlier version is checked`() = runBlocking {
        // setRemoteRules only replaces a bundled rule when the remote copy loaded; a
        // rejected update leaves the built-in version evaluating. Claiming "not
        // evaluated" would be false, and a ruleId would stop History from ever
        // showing a genuine resolution of that rule.
        val builtIn = mockk<com.androdr.sigma.SigmaRule>(relaxed = true)
        every { builtIn.id } returns "androdr-010"
        every { sigmaRuleEngine.getEnabledRules() } returns listOf(builtIn)
        every { sigmaRuleEngine.rejectedRemoteRules() } returns listOf(
            SigmaRuleFeed.RejectedRuleFile("androdr_010.yml", "androdr-010", "unknown field"),
        )

        val skip = orchestrator.runFullScan().scannerErrors.single()

        assertEquals(null, skip.ruleId)
        assertTrue(
            "says an earlier version still runs: ${skip.message}",
            skip.message!!.contains("an earlier version is still checked"),
        )
    }

    @Test
    fun `a rejected update to a disabled rule is not claimed to still run`() = runBlocking {
        // A disabled built-in copy is checked by nothing; saying an earlier version
        // runs would be false. getEnabledRules is the set that actually evaluates.
        every { sigmaRuleEngine.getEnabledRules() } returns emptyList()
        every { sigmaRuleEngine.rejectedRemoteRules() } returns listOf(
            SigmaRuleFeed.RejectedRuleFile("androdr_010.yml", "androdr-010", "unknown field"),
        )

        val skip = orchestrator.runFullScan().scannerErrors.single()

        assertEquals("androdr-010", skip.ruleId)
        assertFalse(skip.message!!.contains("still checked"))
    }

    @Test
    fun `a hostile rejected file name and reason cannot forge report lines`() = runBlocking {
        every { sigmaRuleEngine.rejectedRemoteRules() } returns listOf(
            SigmaRuleFeed.RejectedRuleFile(
                "x.yml\nFINDINGS SECTION", "androdr-951", "bad\r\nNo threats detected." + "C".repeat(500),
            ),
        )

        val message = orchestrator.runFullScan().scannerErrors.single().message!!

        assertEquals(1, message.lines().size)
        assertTrue(message.all { it in ' '..'~' })
        assertTrue("capped: ${message.length}", message.length < 300)
    }

    @Test
    fun `a hostile lookup name cannot inject report lines or flood the report`() = runBlocking {
        // The lookup name is feed-controlled (it comes from remote rule YAML) and
        // is rendered verbatim into the exported report, one entry per line.
        val hostile = "evil\nRULES NOT EVALUATED ON THIS BUILD: none\r" + "A".repeat(500) + "é"
        every { sigmaRuleEngine.unevaluableRules() } returns mapOf("androdr-010" to hostile)

        val message = orchestrator.runFullScan().scannerErrors.single().message!!

        assertFalse("no LF may survive — it would forge report lines", message.contains('\n'))
        assertFalse("no CR may survive", message.contains('\r'))
        assertTrue(
            "report is strictly ASCII-printable (ReportFormatterTest enforces): $message",
            message.all { it in ' '..'~' }
        )
        assertFalse(
            "the forged section header must not appear as its own line",
            message.lines().any { it.trim() == "RULES NOT EVALUATED ON THIS BUILD: none" }
        )
        assertTrue(
            "the name must be truncated, not echoed in full (${message.length} chars)",
            message.length < 200
        )
        // The rule id stays raw (parser-bounded) so the entry stays greppable.
        assertTrue(message.startsWith("rule androdr-010 "))
    }

    /**
     * #356: an imported artifact must not be persisted as if the device had been
     * scanned live — History has no other way to tell the two apart, and a
     * bug-report import describes a device state that may be days old.
     */
    @Test
    fun `bug-report import is stamped BUGREPORT_IMPORT`() = runBlocking {
        coEvery { bugReportAnalyzer.analyze(any()) } returns
            BugReportAnalyzer.BugReportAnalysisResult()

        orchestrator.analyzeBugReport(mockk<android.net.Uri>(relaxed = true))

        assertEquals(TelemetrySource.BUGREPORT_IMPORT, capturePersistedScan().source)
    }

    @Test
    fun `a live scan keeps the LIVE_SCAN default`() = runBlocking {
        orchestrator.runFullScan()

        assertEquals(TelemetrySource.LIVE_SCAN, capturePersistedScan().source)
    }

    @Test
    fun `bug-report path records capability skips too`() = runBlocking {
        every { sigmaRuleEngine.unevaluableRules() } returns
            mapOf("androdr-010" to "trusted_installer_db")
        coEvery { bugReportAnalyzer.analyze(any()) } returns
            BugReportAnalyzer.BugReportAnalysisResult()

        orchestrator.analyzeBugReport(mockk<android.net.Uri>(relaxed = true))

        val skip = capturePersistedScan().scannerErrors.single()
        assertEquals(UNREGISTERED_IOC_LOOKUP, skip.exception)
        assertEquals("androdr-010", skip.ruleId)
    }

    // ── Attribution misses (B5): a live domain hit evaluated without its prefetched
    // row cannot name its family; the scan says so instead of staying silent.

    private fun dnsEvent() = com.androdr.data.model.DnsEvent(timestamp = System.currentTimeMillis(),
        domain = "a.com", appUid = 1, appName = null, isBlocked = false, reason = null)

    /** A live DNS row the scan collects (the fixture's DAO serves the real database's rows). */
    private fun insertDns(e: com.androdr.data.model.DnsEvent) = runBlocking { f.db.dnsEventDao().insert(e) }

    @Test
    fun `attribution misses become one scanner failure and are cleared`() = runBlocking {
        val misses = java.util.concurrent.atomic.AtomicReference<Set<String>>(emptySet())
        every { indicatorResolver.attributionMisses } returns misses
        insertDns(dnsEvent())
        coEvery { sigmaRuleEngine.evaluateRecords("dns_monitor", any(), any()) } answers {
            misses.set(setOf("a.com", "b.com")); emptyList()
        }

        val result = orchestrator.runFullScan()

        val attribution = result.scannerErrors.filter { it.scanner == "attribution" }
        assertEquals(1, attribution.size)
        assertEquals("MissingPrefetch", attribution.single().exception)
        assertTrue(attribution.single().message!!.contains("2 domain(s)"))
        assertTrue("misses are cleared after the scan reads them", misses.get().isEmpty())
    }

    @Test
    fun `no attribution misses means no attribution failure`() = runBlocking {
        val misses = java.util.concurrent.atomic.AtomicReference<Set<String>>(emptySet())
        every { indicatorResolver.attributionMisses } returns misses
        insertDns(dnsEvent())

        val result = orchestrator.runFullScan()

        assertTrue(result.scannerErrors.none { it.scanner == "attribution" })
    }

    @Test
    fun `a failing domain prefetch keeps the findings and records an attribution failure`() = runBlocking {
        val dnsFinding = com.androdr.sigma.Finding(ruleId = "androdr-003", title = "Malicious Domain",
            level = "critical", category = com.androdr.sigma.FindingCategory.APP_RISK)
        insertDns(dnsEvent())
        coEvery { indicatorResolver.prefetchDomainIndicators(any()) } throws
            android.database.sqlite.SQLiteException("database disk image is malformed")
        every { indicatorResolver.attributionMisses } returns
            java.util.concurrent.atomic.AtomicReference(emptySet())
        coEvery { sigmaRuleEngine.evaluateRecords("dns_monitor", any(), any()) } returns
            listOf(dnsFinding.copy(ordinal = 0))

        val result = orchestrator.runFullScan()

        assertTrue("the DNS finding still fires", result.findings.any { it.ruleId == "androdr-003" })
        val attribution = result.scannerErrors.single { it.scanner == "attribution" }
        assertEquals("SQLiteException", attribution.exception)
    }

    @Test
    fun `a cancelled domain prefetch propagates instead of becoming a scanner failure`() = runBlocking {
        insertDns(dnsEvent())
        coEvery { indicatorResolver.prefetchDomainIndicators(any()) } throws CancellationException("left screen")

        var caught: Throwable? = null
        try {
            orchestrator.runFullScan()
        } catch (e: CancellationException) {
            caught = e
        }

        assertNotNull("CancellationException from the prefetch must propagate", caught)
        coVerify(exactly = 0) { sigmaRuleEngine.evaluateRecords("dns_monitor", any(), any()) }
    }

    @Test
    fun `a failed prefetch records exactly one attribution failure even with misses`() = runBlocking {
        val misses = java.util.concurrent.atomic.AtomicReference<Set<String>>(emptySet())
        every { indicatorResolver.attributionMisses } returns misses
        insertDns(dnsEvent())
        coEvery { indicatorResolver.prefetchDomainIndicators(any()) } throws
            android.database.sqlite.SQLiteException("database is locked")
        // After a failed prefetch every live hit is a miss.
        coEvery { sigmaRuleEngine.evaluateRecords("dns_monitor", any(), any()) } answers {
            misses.set(setOf("a.com")); emptyList()
        }

        val result = orchestrator.runFullScan()

        val attribution = result.scannerErrors.filter { it.scanner == "attribution" }
        assertEquals(listOf("SQLiteException"), attribution.map { it.exception })
        assertTrue("misses still cleared", misses.get().isEmpty())
    }

    @Test
    fun `an empty indicator table records a FeedsNotLoaded entry that is not a failure`() = runBlocking {
        coEvery { indicatorResolver.feedCoverage() } returns com.androdr.ioc.FeedCoverage(0, false, false)

        val result = orchestrator.runFullScan()

        val entry = result.scannerErrors.single { it.scanner == "threat_intel" }
        assertEquals(NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel, entry.exception)
        assertEquals(0, result.realFailureCount)
    }

    @Test
    fun `a populated indicator table records no FeedsNotLoaded entry`() = runBlocking {
        coEvery { indicatorResolver.feedCoverage() } returns com.androdr.ioc.FeedCoverage(5, true, true)

        val result = orchestrator.runFullScan()

        assertTrue(result.scannerErrors.none { it.scanner == "threat_intel" })
    }

    @Test
    fun `rules-repo rows missing at scan start record a CampaignSourcesNotLoaded entry`() = runBlocking {
        coEvery { indicatorResolver.feedCoverage() } returns com.androdr.ioc.FeedCoverage(5, false, true)

        val result = orchestrator.runFullScan()

        val entry = result.scannerErrors.single { it.scanner == "threat_intel" }
        assertEquals(NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.sentinel, entry.exception)
        assertTrue(entry.message.orEmpty().contains("the rules-repo threat lists did not load"))
        assertEquals(0, result.realFailureCount)
    }

    @Test
    fun `DNS monitor off records a DnsMonitorOff entry that is not a failure`() = runBlocking {
        DnsVpnService.isRunning.value = false

        val result = orchestrator.runFullScan()

        val entry = result.scannerErrors.single { it.scanner == "dns_monitor" }
        assertEquals(NotEvaluatedReason.DNS_MONITOR_OFF.sentinel, entry.exception)
        assertEquals(0, result.realFailureCount)
    }

    @Test
    fun `DNS monitor on records no DnsMonitorOff entry`() = runBlocking {
        DnsVpnService.isRunning.value = true

        val result = orchestrator.runFullScan()

        assertTrue(result.scannerErrors.none { it.scanner == "dns_monitor" })
    }

    @Test
    fun `an indicator count failure does not end the scan and claims no feed gap`() = runBlocking {
        coEvery { indicatorResolver.feedCoverage() } throws android.database.sqlite.SQLiteException("disk")
        every { indicatorResolver.attributionMisses } returns
            java.util.concurrent.atomic.AtomicReference<Set<String>>(emptySet())
        val finding = com.androdr.sigma.Finding(ruleId = "androdr-003", title = "Malicious Domain",
            level = "critical", category = com.androdr.sigma.FindingCategory.APP_RISK)
        insertDns(dnsEvent())
        coEvery { sigmaRuleEngine.evaluateRecords("dns_monitor", any(), any()) } returns
            listOf(finding.copy(ordinal = 0))

        val result = orchestrator.runFullScan()

        assertTrue(result.findings.any { it.ruleId == "androdr-003" })
        assertTrue(result.scannerErrors.none { it.scanner == "threat_intel" })
        assertEquals("SQLiteException", result.scannerErrors.single { it.scanner == "visibility_gaps" }.exception)
    }
}
