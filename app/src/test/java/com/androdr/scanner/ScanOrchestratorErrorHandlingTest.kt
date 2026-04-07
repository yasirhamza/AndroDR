package com.androdr.scanner

import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.ScanResultDao
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.ScanRepository
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.KnownAppResolver
import com.androdr.ioc.OemPrefixResolver
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import io.mockk.coEvery
import io.mockk.coJustRun
import io.mockk.every
import io.mockk.mockk
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
        dnsEventDao = mockk(relaxed = true)
        forensicTimelineEventDao = mockk(relaxed = true)
        sigmaRuleEngine = mockk(relaxed = true)
        indicatorResolver = mockk(relaxed = true)
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
            scanRepository = scanRepository,
            dnsEventDao = dnsEventDao,
            forensicTimelineEventDao = forensicTimelineEventDao,
            sigmaRuleEngine = sigmaRuleEngine,
            indicatorResolver = indicatorResolver,
            sigmaRuleFeed = sigmaRuleFeed,
            knownAppResolver = knownAppResolver,
            oemPrefixResolver = oemPrefixResolver
        )
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
}
