package com.androdr.scanner

import android.content.Context
import com.androdr.data.db.DnsEventDao
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.ScanLock
import com.androdr.ioc.FeedCoverage
import com.androdr.ioc.IndicatorResolver
import com.androdr.network.DnsVpnService
import com.androdr.sigma.SigmaCorrelationEngine
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import io.mockk.coEvery
import io.mockk.mockk
import java.io.Closeable

/**
 * A [ScanOrchestrator] whose writer session runs on a real in-memory Room database
 * ([WriterFixture]; callers use RobolectricTestRunner), with every other collaborator a relaxed mock
 * the test may stub: the scanners behind a real [LiveScanCollector], the analyzers, and [engine].
 * [engine] defaults to a relaxed mock — stub `evaluateRecords(service, any(), any())` for findings —
 * or pass a real [SigmaRuleEngine].
 */
internal class OrchestratorFixture(
    val engine: SigmaRuleEngine = mockk(relaxed = true),
    val correlationEngine: SigmaCorrelationEngine = mockk(relaxed = true),
    val bugReportAnalyzer: BugReportAnalyzer = mockk(relaxed = true),
    intrusionLogAnalyzer: IntrusionLogAnalyzer? = null,
    recordSql: Boolean = true,
) : Closeable {
    val w = WriterFixture(recordSql)
    val db get() = w.f.db
    val timelineDao get() = w.f.db.forensicTimelineEventDao()

    val appScanner: AppScanner = mockk(relaxed = true)
    val deviceAuditor: DeviceAuditor = mockk(relaxed = true)
    val processScanner: ProcessScanner = mockk(relaxed = true)
    val fileArtifactScanner: FileArtifactScanner = mockk(relaxed = true)
    val accessibilityAuditScanner: AccessibilityAuditScanner = mockk(relaxed = true)
    val receiverAuditScanner: ReceiverAuditScanner = mockk(relaxed = true)
    val appOpsScanner: AppOpsScanner = mockk(relaxed = true)
    /** Usage Access granted, no events, unless a test stubs `collectEvents(any(), any())`. */
    val usageStatsScanner: UsageStatsScanner = mockk<UsageStatsScanner>(relaxed = true).also {
        coEvery { it.collectEvents(any(), any()) } returns UsageCollection.Ok(emptyList())
    }
    /**
     * Serves the real database's live DNS rows (tests insert them through `db.dnsEventDao()`);
     * stub a method to make a read fail.
     */
    val dnsEventDao: DnsEventDao = mockk<DnsEventDao>(relaxed = true).also { dao ->
        coEvery { dao.maxId() } coAnswers { db.dnsEventDao().maxId() }
        coEvery { dao.minIdSince(any()) } coAnswers { db.dnsEventDao().minIdSince(firstArg()) }
        coEvery { dao.eventsAfterId(any(), any(), any()) } coAnswers {
            db.dnsEventDao().eventsAfterId(firstArg(), secondArg(), thirdArg())
        }
    }
    val installEventEmitter: InstallEventEmitter = mockk(relaxed = true)
    val deviceAdminGrantEmitter: DeviceAdminGrantEmitter = mockk(relaxed = true)
    val sigmaRuleFeed: SigmaRuleFeed = mockk(relaxed = true)
    val context: Context = mockk(relaxed = true)
    val lock = ScanLock()

    val indicatorResolver: IndicatorResolver = mockk<IndicatorResolver>(relaxed = true).also {
        // B6: an empty indicator table adds a FeedsNotLoaded entry; these tests are about other things.
        coEvery { it.feedCoverage() } returns FeedCoverage(1, true, true)
        io.mockk.every { it.attributionMisses } returns java.util.concurrent.atomic.AtomicReference(emptySet())
    }

    /** A mock unless given; a real one reads the URI through [context] (see [serving]). */
    val intrusionLogAnalyzer: IntrusionLogAnalyzer = intrusionLogAnalyzer ?: mockk(relaxed = true)

    val writer by lazy { ChunkedScanWriter(engine, w.store, w.repo, w.f.findings, w.preflight, w.health) }

    init {
        // DnsVpnService.isRunning (JVM-global, defaults false) adds a DnsMonitorOff entry otherwise.
        DnsVpnService.isRunning.value = true
        // initRuleEngine reloads the rules (bundled: none under a mock context, then the feed's), so
        // the feed serves whatever rules a real [engine] was given.
        val rules = engine.getRules()
        coEvery { sigmaRuleFeed.fetch() } returns rules
    }

    val orchestrator: ScanOrchestrator by lazy {
        ScanOrchestrator(
            collector = LiveScanCollector(
                appScanner, deviceAuditor, processScanner, fileArtifactScanner, accessibilityAuditScanner,
                receiverAuditScanner, appOpsScanner, usageStatsScanner, dnsEventDao, db.eventWatermarkDao(),
            ),
            appScanner = appScanner,
            bugReportAnalyzer = bugReportAnalyzer,
            intrusionLogAnalyzer = this.intrusionLogAnalyzer,
            writer = writer,
            scanLock = lock,
            installEventEmitter = installEventEmitter,
            deviceAdminGrantEmitter = deviceAdminGrantEmitter,
            sigmaRuleEngine = engine,
            sigmaCorrelationEngine = correlationEngine,
            indicatorResolver = indicatorResolver,
            sigmaRuleFeed = sigmaRuleFeed,
            knownAppResolver = mockk(relaxed = true),
            oemPrefixResolver = mockk(relaxed = true),
            brandImpersonationResolver = mockk(relaxed = true),
            telemetryReader = w.f.reader,
            context = context,
        )
    }

    /** Every scan row, newest first (including ones a test expects to be hidden). */
    suspend fun scans(): List<ScanResult> = db.scanResultDao().getLatestTwo()

    fun count(sql: String): Long = w.count(sql)

    /** Every finding of COMPLETE scan [scanId], read back from `scan_finding`. */
    suspend fun findingsOf(scanId: Long) = w.findingsOf(scanId)

    companion object {
        /** A minimal live app record. */
        fun app(pkg: String, sideloaded: Boolean = false) = com.androdr.data.model.AppTelemetry(
            packageName = pkg, appName = pkg, certHash = null, certHashSha1 = null, apkHash = null,
            isSystemApp = false, fromTrustedStore = false, installer = null, isSideloaded = sideloaded,
            isKnownOemApp = false, permissions = emptyList(), surveillancePermissionCount = 0,
            hasAccessibilityService = false, hasDeviceAdmin = false, knownAppCategory = null,
            source = com.androdr.data.model.TelemetrySource.LIVE_SCAN,
        )

        /** A context whose content resolver serves [bytes] for any URI (a fresh stream per open). */
        fun serving(bytes: () -> java.io.InputStream): Context {
            val resolver = mockk<android.content.ContentResolver>()
            io.mockk.every { resolver.openInputStream(any()) } answers { bytes() }
            val ctx = mockk<Context>(relaxed = true)
            io.mockk.every { ctx.contentResolver } returns resolver
            return ctx
        }
    }

    override fun close() {
        DnsVpnService.isRunning.value = false
        w.close()
    }
}
