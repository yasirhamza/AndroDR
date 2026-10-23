package com.androdr.scanner

import org.junit.After
import com.androdr.network.DnsVpnService
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.ScanResultDao
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.UNREGISTERED_IOC_LOOKUP
import com.androdr.data.repo.ScanRepository
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.KnownAppResolver
import com.androdr.ioc.OemPrefixResolver
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import io.mockk.coEvery
import io.mockk.coJustRun
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

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
 * Mutation-tested: reverting `trackScanner` to the old
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
class ScanOrchestratorErrorHandlingTest {

    private lateinit var appScanner: AppScanner
    private lateinit var deviceAuditor: DeviceAuditor
    private lateinit var processScanner: ProcessScanner
    private lateinit var fileArtifactScanner: FileArtifactScanner
    private lateinit var accessibilityAuditScanner: AccessibilityAuditScanner
    private lateinit var receiverAuditScanner: ReceiverAuditScanner
    private lateinit var appOpsScanner: AppOpsScanner
    private lateinit var usageStatsScanner: UsageStatsScanner
    private lateinit var bugReportAnalyzer: BugReportAnalyzer
    private lateinit var scanRepository: ScanRepository
    private lateinit var dnsEventDao: DnsEventDao
    private lateinit var forensicTimelineEventDao: ForensicTimelineEventDao
    private lateinit var sigmaRuleEngine: SigmaRuleEngine
    private lateinit var indicatorResolver: IndicatorResolver
    private lateinit var sigmaRuleFeed: SigmaRuleFeed
    private lateinit var knownAppResolver: KnownAppResolver
    private lateinit var oemPrefixResolver: OemPrefixResolver
    private lateinit var scanResultDao: ScanResultDao

    private lateinit var orchestrator: ScanOrchestrator

    @Suppress("LongMethod") // Stubs for ~17 collaborators — splitting adds no clarity
    @Before
    fun setUp() {
        appScanner = mockk(relaxed = true)
        deviceAuditor = mockk(relaxed = true)
        processScanner = mockk(relaxed = true)
        fileArtifactScanner = mockk(relaxed = true)
        accessibilityAuditScanner = mockk(relaxed = true)
        receiverAuditScanner = mockk(relaxed = true)
        appOpsScanner = mockk(relaxed = true)
        usageStatsScanner = mockk(relaxed = true)
        bugReportAnalyzer = mockk(relaxed = true)
        scanRepository = mockk(relaxed = true)
        // #350: saveScanWithCorrelation returns the persisted scan, which runFullScan
        // now hands back to its caller. A relaxed mock would return a hollow
        // ScanResult, so model the real contract: give back the scan it was given.
        coEvery {
            scanRepository.saveScanWithCorrelation(any(), any(), any(), any(), any(), any(), any())
        } coAnswers { firstArg() }
        dnsEventDao = mockk(relaxed = true)
        forensicTimelineEventDao = mockk(relaxed = true)
        sigmaRuleEngine = mockk(relaxed = true)
        indicatorResolver = mockk(relaxed = true)
        // B6: an empty indicator table adds a FeedsNotLoaded entry; these tests are about
        // other things. DnsVpnService.isRunning (JVM-global, defaults false) likewise adds DnsMonitorOff.
        coEvery { indicatorResolver.feedCoverage() } returns com.androdr.ioc.FeedCoverage(1, true, true)
        DnsVpnService.isRunning.value = true
        sigmaRuleFeed = mockk(relaxed = true)
        knownAppResolver = mockk(relaxed = true)
        oemPrefixResolver = mockk(relaxed = true)
        scanResultDao = mockk(relaxed = true)

        // Happy defaults: every scanner returns an empty list, every sink
        // accepts any argument. Individual tests override these to throw.
        coEvery { appScanner.collectTelemetry() } returns emptyList()
        coEvery { deviceAuditor.collectTelemetry() } returns emptyList()
        coEvery { processScanner.collectTelemetry() } returns emptyList()
        coEvery { fileArtifactScanner.collectTelemetry() } returns emptyList()
        coEvery { accessibilityAuditScanner.collectTelemetry() } returns emptyList()
        coEvery { receiverAuditScanner.collectTelemetry() } returns emptyList()
        coEvery { appOpsScanner.collectTelemetry() } returns emptyList()
        coEvery { usageStatsScanner.collectTimelineEvents() } returns emptyList()
        coEvery { dnsEventDao.getRecentSnapshot() } returns emptyList()
        coJustRun { scanRepository.saveScan(any()) }
        coJustRun { forensicTimelineEventDao.insertAll(any()) }
        coJustRun { forensicTimelineEventDao.deleteBySource(any()) }
        coEvery { sigmaRuleFeed.fetch() } returns emptyList()
        coEvery { sigmaRuleEngine.evaluateApps(any()) } returns emptyList()
        coEvery { sigmaRuleEngine.evaluateDevice(any()) } returns emptyList()
        coEvery { sigmaRuleEngine.evaluateProcesses(any()) } returns emptyList()
        coEvery { sigmaRuleEngine.evaluateFiles(any()) } returns emptyList()
        coEvery { sigmaRuleEngine.evaluateAccessibility(any()) } returns emptyList()
        coEvery { sigmaRuleEngine.evaluateReceivers(any()) } returns emptyList()
        coEvery { sigmaRuleEngine.evaluateAppOps(any()) } returns emptyList()
        coEvery { sigmaRuleEngine.evaluateDns(any()) } returns emptyList()
        every { sigmaRuleEngine.getRules() } returns emptyList()
        // ruleCount(), loadBundledRules(), setIocLookups(), setRemoteRules(),
        // setEvidenceProviders() are covered by the mockk `relaxed = true` default
        // return values — no explicit stubs needed.

        orchestrator = ScanOrchestrator(
            appScanner = appScanner,
            deviceAuditor = deviceAuditor,
            processScanner = processScanner,
            fileArtifactScanner = fileArtifactScanner,
            accessibilityAuditScanner = accessibilityAuditScanner,
            receiverAuditScanner = receiverAuditScanner,
            appOpsScanner = appOpsScanner,
            usageStatsScanner = usageStatsScanner,
            bugReportAnalyzer = bugReportAnalyzer,
            intrusionLogAnalyzer = mockk(relaxed = true),
            scanRepository = scanRepository,
            dnsEventDao = dnsEventDao,
            forensicTimelineEventDao = mockk(relaxed = true),
            timelineRows = mockk(relaxed = true),
            installEventEmitter = mockk(relaxed = true),
            deviceAdminGrantEmitter = mockk(relaxed = true),
            sigmaRuleEngine = sigmaRuleEngine,
            sigmaCorrelationEngine = mockk(relaxed = true),
            indicatorResolver = indicatorResolver,
            sigmaRuleFeed = sigmaRuleFeed,
            knownAppResolver = knownAppResolver,
            oemPrefixResolver = oemPrefixResolver,
            brandImpersonationResolver = mockk(relaxed = true),
            context = mockk(relaxed = true)
        )
    }

    @After
    fun resetVpnState() {
        DnsVpnService.isRunning.value = false
    }

    @Test
    fun `scanner exception is recorded in scannerErrors instead of being swallowed`() = runTest {
        val boom = IllegalStateException("boom — simulated scanner crash")
        coEvery { appScanner.collectTelemetry() } throws boom

        val result: ScanResult = orchestrator.runFullScan()

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
    fun `a failed DNS snapshot read is recorded as dnsSnapshot and the scan completes`() = runTest {
        coEvery { dnsEventDao.getRecentSnapshot() } throws IllegalStateException("database is locked")

        val result: ScanResult = orchestrator.runFullScan()

        val failure = result.scannerErrors.single { it.scanner == "dnsSnapshot" }
        assertEquals("IllegalStateException", failure.exception)
        assertEquals("database is locked", failure.message)
        assertTrue("DNS rules did not run: the scan is partial", result.isPartialScan)
    }

    @Test
    fun `cancellation during the DNS snapshot read propagates`() = runTest {
        coEvery { dnsEventDao.getRecentSnapshot() } throws CancellationException("user cancelled")
        var caught: Throwable? = null
        try { orchestrator.runFullScan() } catch (e: CancellationException) { caught = e }
        assertNotNull(caught)
    }

    @Test
    fun `one scanner failing does not cascade — other scanners still run and get recorded`() = runTest {
        coEvery { fileArtifactScanner.collectTelemetry() } throws RuntimeException("file scanner dead")

        val result: ScanResult = orchestrator.runFullScan()

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
        io.mockk.coVerify(exactly = 1) { usageStatsScanner.collectTimelineEvents() }
    }

    @Test
    fun `multiple scanners can fail independently and all failures are recorded`() = runTest {
        coEvery { appScanner.collectTelemetry() } throws RuntimeException("a")
        coEvery { deviceAuditor.collectTelemetry() } throws IllegalStateException("b")
        coEvery { processScanner.collectTelemetry() } throws NullPointerException("c")

        val result: ScanResult = orchestrator.runFullScan()

        assertEquals(3, result.scannerErrors.size)
        val scannerNames = result.scannerErrors.map { it.scanner }.toSet()
        assertTrue(scannerNames.contains("appScanner"))
        assertTrue(scannerNames.contains("deviceAuditor"))
        assertTrue(scannerNames.contains("processScanner"))
    }

    @Test
    fun `CancellationException propagates and is not swallowed as a scanner failure`() = runTest {
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
    fun `successful scan has empty scannerErrors and is not marked partial`() = runTest {
        val result: ScanResult = orchestrator.runFullScan()

        assertFalse(result.isPartialScan)
        assertTrue(result.scannerErrors.isEmpty())
    }

    @Test
    fun `scanProgress returns to Idle after a successful scan`() = runTest {
        orchestrator.runFullScan()
        assertEquals(ScanProgress.Idle, orchestrator.scanProgress.value)
    }

    @Test
    fun `scanProgress returns to Idle even when a scanner throws`() = runTest {
        coEvery { appScanner.collectTelemetry() } throws RuntimeException("boom")
        orchestrator.runFullScan()
        assertEquals(ScanProgress.Idle, orchestrator.scanProgress.value)
    }

    // ---- Capability skips (#136 R1) ------------------------------------------

    /** The ScanResult actually handed to the repository for persistence. */
    private suspend fun capturePersistedScan(): ScanResult {
        val persisted = slot<ScanResult>()
        coVerify {
            scanRepository.saveScanWithCorrelation(
                scan = capture(persisted),
                findingTimelineEvents = any(),
                replaceUsageStatsEvents = any(),
                lookbackEvents = any(),
                findingsForSignals = any(),
                correlator = any()
            )
        }
        return persisted.captured
    }

    @Test
    fun `capability skip is recorded on the persisted scan and does not mark it partial`() = runTest {
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
    fun `capability skips coexist with a real scanner failure without inflating its count`() = runTest {
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
    fun `a rejected remote rule with no built-in copy is declared not evaluated, by id`() = runTest {
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
    fun `a rejected update to a rule that still runs says an earlier version is checked`() = runTest {
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
    fun `a rejected update to a disabled rule is not claimed to still run`() = runTest {
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
    fun `a hostile rejected file name and reason cannot forge report lines`() = runTest {
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
    fun `a hostile lookup name cannot inject report lines or flood the report`() = runTest {
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
    fun `bug-report import is stamped BUGREPORT_IMPORT`() = runTest {
        coEvery { bugReportAnalyzer.analyze(any()) } returns
            BugReportAnalyzer.BugReportAnalysisResult(findings = emptyList(), timeline = emptyList())

        orchestrator.analyzeBugReport(mockk(relaxed = true))

        assertEquals(TelemetrySource.BUGREPORT_IMPORT, capturePersistedScan().source)
    }

    @Test
    fun `a live scan keeps the LIVE_SCAN default`() = runTest {
        orchestrator.runFullScan()

        assertEquals(TelemetrySource.LIVE_SCAN, capturePersistedScan().source)
    }

    @Test
    fun `bug-report path records capability skips too`() = runTest {
        every { sigmaRuleEngine.unevaluableRules() } returns
            mapOf("androdr-010" to "trusted_installer_db")
        coEvery { bugReportAnalyzer.analyze(any()) } returns
            BugReportAnalyzer.BugReportAnalysisResult(findings = emptyList(), timeline = emptyList())

        orchestrator.analyzeBugReport(mockk(relaxed = true))

        val skip = capturePersistedScan().scannerErrors.single()
        assertEquals(UNREGISTERED_IOC_LOOKUP, skip.exception)
        assertEquals("androdr-010", skip.ruleId)
    }

    // ── Attribution misses (B5): a live domain hit evaluated without its prefetched
    // row cannot name its family; the scan says so instead of staying silent.

    private fun dnsEvent() = com.androdr.data.model.DnsEvent(timestamp = 1L, domain = "a.com", appUid = 1,
        appName = null, isBlocked = false, reason = null)

    @Test
    fun `attribution misses become one scanner failure and are cleared`() = runTest {
        val misses = java.util.concurrent.atomic.AtomicReference<Set<String>>(emptySet())
        every { indicatorResolver.attributionMisses } returns misses
        coEvery { dnsEventDao.getRecentSnapshot() } returns listOf(dnsEvent())
        coEvery { sigmaRuleEngine.evaluateDns(any()) } answers {
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
    fun `no attribution misses means no attribution failure`() = runTest {
        val misses = java.util.concurrent.atomic.AtomicReference<Set<String>>(emptySet())
        every { indicatorResolver.attributionMisses } returns misses
        coEvery { dnsEventDao.getRecentSnapshot() } returns listOf(dnsEvent())

        val result = orchestrator.runFullScan()

        assertTrue(result.scannerErrors.none { it.scanner == "attribution" })
    }

    @Test
    fun `a failing domain prefetch keeps the findings and records an attribution failure`() = runTest {
        val dnsFinding = com.androdr.sigma.Finding(ruleId = "androdr-003", title = "Malicious Domain",
            level = "critical", category = com.androdr.sigma.FindingCategory.APP_RISK)
        coEvery { dnsEventDao.getRecentSnapshot() } returns listOf(dnsEvent())
        coEvery { indicatorResolver.prefetchDomainIndicators(any()) } throws
            android.database.sqlite.SQLiteException("database disk image is malformed")
        every { indicatorResolver.attributionMisses } returns
            java.util.concurrent.atomic.AtomicReference(emptySet())
        coEvery { sigmaRuleEngine.evaluateDns(any()) } returns listOf(dnsFinding)

        val result = orchestrator.runFullScan()

        assertTrue("the DNS finding still fires", result.findings.any { it.ruleId == "androdr-003" })
        val attribution = result.scannerErrors.single { it.scanner == "attribution" }
        assertEquals("SQLiteException", attribution.exception)
    }

    @Test
    fun `a cancelled domain prefetch propagates instead of becoming a scanner failure`() = runTest {
        coEvery { dnsEventDao.getRecentSnapshot() } returns listOf(dnsEvent())
        coEvery { indicatorResolver.prefetchDomainIndicators(any()) } throws CancellationException("left screen")

        var caught: Throwable? = null
        try {
            orchestrator.runFullScan()
        } catch (e: CancellationException) {
            caught = e
        }

        assertNotNull("CancellationException from the prefetch must propagate", caught)
        coVerify(exactly = 0) { sigmaRuleEngine.evaluateDns(any()) }
    }

    @Test
    fun `a failed prefetch records exactly one attribution failure even with misses`() = runTest {
        val misses = java.util.concurrent.atomic.AtomicReference<Set<String>>(emptySet())
        every { indicatorResolver.attributionMisses } returns misses
        coEvery { dnsEventDao.getRecentSnapshot() } returns listOf(dnsEvent())
        coEvery { indicatorResolver.prefetchDomainIndicators(any()) } throws
            android.database.sqlite.SQLiteException("database is locked")
        // After a failed prefetch every live hit is a miss.
        coEvery { sigmaRuleEngine.evaluateDns(any()) } answers { misses.set(setOf("a.com")); emptyList() }

        val result = orchestrator.runFullScan()

        val attribution = result.scannerErrors.filter { it.scanner == "attribution" }
        assertEquals(listOf("SQLiteException"), attribution.map { it.exception })
        assertTrue("misses still cleared", misses.get().isEmpty())
    }

    @Test
    fun `an empty indicator table records a FeedsNotLoaded entry that is not a failure`() = runTest {
        coEvery { indicatorResolver.feedCoverage() } returns com.androdr.ioc.FeedCoverage(0, false, false)

        val result = orchestrator.runFullScan()

        val entry = result.scannerErrors.single { it.scanner == "threat_intel" }
        assertEquals(NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel, entry.exception)
        assertEquals(0, result.realFailureCount)
    }

    @Test
    fun `a populated indicator table records no FeedsNotLoaded entry`() = runTest {
        coEvery { indicatorResolver.feedCoverage() } returns com.androdr.ioc.FeedCoverage(5, true, true)

        val result = orchestrator.runFullScan()

        assertTrue(result.scannerErrors.none { it.scanner == "threat_intel" })
    }

    @Test
    fun `rules-repo rows missing at scan start record a CampaignSourcesNotLoaded entry`() = runTest {
        coEvery { indicatorResolver.feedCoverage() } returns com.androdr.ioc.FeedCoverage(5, false, true)

        val result = orchestrator.runFullScan()

        val entry = result.scannerErrors.single { it.scanner == "threat_intel" }
        assertEquals(NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.sentinel, entry.exception)
        assertTrue(entry.message.orEmpty().contains("the rules-repo threat lists did not load"))
        assertEquals(0, result.realFailureCount)
    }

    @Test
    fun `DNS monitor off records a DnsMonitorOff entry that is not a failure`() = runTest {
        DnsVpnService.isRunning.value = false

        val result = orchestrator.runFullScan()

        val entry = result.scannerErrors.single { it.scanner == "dns_monitor" }
        assertEquals(NotEvaluatedReason.DNS_MONITOR_OFF.sentinel, entry.exception)
        assertEquals(0, result.realFailureCount)
    }

    @Test
    fun `DNS monitor on records no DnsMonitorOff entry`() = runTest {
        DnsVpnService.isRunning.value = true

        val result = orchestrator.runFullScan()

        assertTrue(result.scannerErrors.none { it.scanner == "dns_monitor" })
    }

    @Test
    fun `an indicator count failure does not end the scan and claims no feed gap`() = runTest {
        coEvery { indicatorResolver.feedCoverage() } throws android.database.sqlite.SQLiteException("disk")
        every { indicatorResolver.attributionMisses } returns
            java.util.concurrent.atomic.AtomicReference<Set<String>>(emptySet())
        val finding = com.androdr.sigma.Finding(ruleId = "androdr-003", title = "Malicious Domain",
            level = "critical", category = com.androdr.sigma.FindingCategory.APP_RISK)
        coEvery { dnsEventDao.getRecentSnapshot() } returns listOf(dnsEvent())
        coEvery { sigmaRuleEngine.evaluateDns(any()) } returns listOf(finding)

        val result = orchestrator.runFullScan()

        assertTrue(result.findings.any { it.ruleId == "androdr-003" })
        assertTrue(result.scannerErrors.none { it.scanner == "threat_intel" })
        assertEquals("SQLiteException", result.scannerErrors.single { it.scanner == "visibility_gaps" }.exception)
    }
}
