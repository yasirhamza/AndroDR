package com.androdr.scanner

import android.net.Uri
import android.util.Log
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.ScanRepository
import com.androdr.ioc.IndicatorResolver
import com.androdr.sigma.CveEvidenceProvider
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.SigmaRuleFeed
import com.androdr.sigma.SigmaRuleEngine
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Orchestrates all scanning operations.  Runs [AppScanner] and [DeviceAuditor] in parallel,
 * assembles a [ScanResult], persists it, and exposes helpers for bug-report analysis and
 * result diffing.
 */
@Singleton
@Suppress("LongParameterList") // All parameters are Hilt-injected dependencies
class ScanOrchestrator @Inject constructor(
    private val appScanner: AppScanner,
    private val deviceAuditor: DeviceAuditor,
    private val processScanner: ProcessScanner,
    private val fileArtifactScanner: FileArtifactScanner,
    private val accessibilityAuditScanner: AccessibilityAuditScanner,
    private val receiverAuditScanner: ReceiverAuditScanner,
    private val appOpsScanner: AppOpsScanner,
    private val usageStatsScanner: UsageStatsScanner,
    private val bugReportAnalyzer: BugReportAnalyzer,
    private val scanRepository: ScanRepository,
    private val dnsEventDao: DnsEventDao,
    private val forensicTimelineEventDao: ForensicTimelineEventDao,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val indicatorResolver: IndicatorResolver,
    private val sigmaRuleFeed: SigmaRuleFeed,
    private val knownAppResolver: com.androdr.ioc.KnownAppResolver,
    private val oemPrefixResolver: com.androdr.ioc.OemPrefixResolver
) {

    private val initMutex = Mutex()
    private var ruleEngineInitialized = false

    /** Cached app telemetry from the most recent scan, for report export. */
    @Volatile var lastAppTelemetry: List<com.androdr.data.model.AppTelemetry> = emptyList()
        private set

    private suspend fun initRuleEngine() = initMutex.withLock {
        if (ruleEngineInitialized) return@withLock
        sigmaRuleEngine.setIocLookups(mapOf(
            "package_ioc_db" to { v -> indicatorResolver.isKnownBadPackage(v.toString()) != null },
            "cert_hash_ioc_db" to { v -> indicatorResolver.isKnownBadCert(v.toString()) != null },
            "domain_ioc_db" to { v -> indicatorResolver.isKnownBadDomain(v.toString()) != null },
            "apk_hash_ioc_db" to { v -> indicatorResolver.isKnownBadApkHash(v.toString()) != null },
            // ADR: package-name-only lookup, no cert verification. The trusted installer
            // (from_trusted_store) is the trust anchor — Android enforces signature consistency
            // for same-package installs, so Play Store attestation guarantees authenticity.
            // See issue #51 for full rationale.
            "known_good_app_db" to { v ->
                val pkg = v.toString()
                val entry = knownAppResolver.lookup(pkg)
                (entry != null && entry.category in TRUSTED_CATEGORIES) ||
                    oemPrefixResolver.isOemPrefix(pkg)
            }
        ))
        sigmaRuleEngine.loadBundledRules()
        // Fetch remote rules in background — non-blocking, failures are silent
        @Suppress("TooGenericExceptionCaught")
        try {
            val remoteRules = sigmaRuleFeed.fetch()
            if (remoteRules.isNotEmpty()) {
                sigmaRuleEngine.setRemoteRules(remoteRules)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Remote SIGMA rule fetch failed: ${e.message}")
        }
        sigmaRuleEngine.setEvidenceProviders(mapOf(
            "cve_list" to CveEvidenceProvider(sigmaRuleEngine.getRules())
        ))
        ruleEngineInitialized = true
    }

    /**
     * Runs a full device scan.
     *
     * [AppScanner.collectTelemetry] and [DeviceAuditor.collectTelemetry] execute concurrently on the IO dispatcher
     * (each is already wrapped with [kotlinx.coroutines.withContext]).  The results are combined
     * into a [ScanResult], saved to the database, and returned.
     */
    @Suppress("LongMethod") // Two-phase scan: telemetry collection + SIGMA rule evaluation
    suspend fun runFullScan(): ScanResult = coroutineScope {
        initRuleEngine()

        // Phase 1: Collect telemetry (no detection logic)
        val appTelemetryDeferred = async {
            runCatching { appScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
        val deviceTelemetryDeferred = async {
            runCatching { deviceAuditor.collectTelemetry() }.getOrDefault(emptyList())
        }
        val processTelemetryDeferred = async {
            runCatching { processScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
        val fileTelemetryDeferred = async {
            runCatching { fileArtifactScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
        val accessibilityTelemetryDeferred = async {
            runCatching { accessibilityAuditScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
        val receiverTelemetryDeferred = async {
            runCatching { receiverAuditScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
        val appOpsTelemetryDeferred = async {
            runCatching { appOpsScanner.collectTelemetry() }.getOrDefault(emptyList())
        }
        val usageEventsDeferred = async {
            runCatching { usageStatsScanner.collectTimelineEvents() }.getOrDefault(emptyList())
        }

        val appTelemetry = appTelemetryDeferred.await()
        lastAppTelemetry = appTelemetry // cache for report export
        val deviceTelemetry = deviceTelemetryDeferred.await()
        val processTelemetry = processTelemetryDeferred.await()
        val fileTelemetry = fileTelemetryDeferred.await()
        val accessibilityTelemetry = accessibilityTelemetryDeferred.await()
        val receiverTelemetry = receiverTelemetryDeferred.await()
        val appOpsTelemetry = appOpsTelemetryDeferred.await()

        // Phase 2: SIGMA rule evaluation — all detection via rules
        val allFindings = mutableListOf<Finding>()
        allFindings.addAll(sigmaRuleEngine.evaluateApps(appTelemetry))
        allFindings.addAll(sigmaRuleEngine.evaluateDevice(deviceTelemetry))
        allFindings.addAll(sigmaRuleEngine.evaluateProcesses(processTelemetry))
        allFindings.addAll(sigmaRuleEngine.evaluateFiles(fileTelemetry))
        allFindings.addAll(sigmaRuleEngine.evaluateAccessibility(accessibilityTelemetry))
        allFindings.addAll(sigmaRuleEngine.evaluateReceivers(receiverTelemetry))
        allFindings.addAll(sigmaRuleEngine.evaluateAppOps(appOpsTelemetry))

        // Post-hoc DNS evaluation — SIGMA rules evaluate recent DNS events for reporting
        val recentDnsEvents = runCatching {
            dnsEventDao.getRecentSnapshot()
        }.getOrDefault(emptyList())
        if (recentDnsEvents.isNotEmpty()) {
            allFindings.addAll(sigmaRuleEngine.evaluateDns(recentDnsEvents))
        }

        val sideloadedCount = allFindings.count {
            it.category == FindingCategory.APP_RISK && it.matchContext["is_sideloaded"] == "true"
        }
        val malwareCount = allFindings.count {
            it.level == "critical" && it.ruleId in KNOWN_MALWARE_RULE_IDS
        }

        Log.i(TAG, "Scan complete — SIGMA: ${allFindings.size} findings from " +
            "${sigmaRuleEngine.ruleCount()} rules")

        val now = System.currentTimeMillis()
        val result = ScanResult(
            id                 = now,
            timestamp          = now,
            findings           = allFindings,
            bugReportFindings  = emptyList(),
            riskySideloadCount = sideloadedCount,
            knownMalwareCount  = malwareCount
        )

        runCatching { scanRepository.saveScan(result) }
            .onFailure { Log.e(TAG, "Failed to save scan result", it) }
        runCatching {
            // Build hash lookup from app telemetry for enrichment
            val hashByPkg = appTelemetry.filter { !it.apkHash.isNullOrEmpty() }
                .associateBy({ it.packageName }, { it.apkHash!! })
            val timelineEvents = allFindings
                .filter { it.triggered }
                .map { finding ->
                    val event = finding.toForensicTimelineEvent(result)
                    // Enrich with APK hash from telemetry if not already set
                    if (event.apkHash.isEmpty() && event.packageName.isNotEmpty()) {
                        event.copy(apkHash = hashByPkg[event.packageName] ?: "")
                    } else event
                }
            if (timelineEvents.isNotEmpty()) {
                forensicTimelineEventDao.insertAll(timelineEvents)
                Log.i(TAG, "Persisted ${timelineEvents.size} timeline events for scan ${result.id}")
            }
        }.onFailure { Log.e(TAG, "Failed to persist timeline events", it) }

        // Usage stats produce timeline events directly (observational data, not SIGMA telemetry)
        val usageEvents = usageEventsDeferred.await()
        if (usageEvents.isNotEmpty()) {
            val tagged = usageEvents.map { it.copy(scanResultId = result.id) }
            // Remove stale usage_stats events before inserting fresh ones
            runCatching {
                forensicTimelineEventDao.deleteBySource("usage_stats")
            }.onFailure { Log.e(TAG, "Failed to delete stale usage events", it) }
            runCatching { forensicTimelineEventDao.insertAll(tagged) }
                .onFailure { Log.e(TAG, "Failed to persist usage events", it) }
        }

        result
    }

    /**
     * Analyzes a bug report, evaluates telemetry through SIGMA rules,
     * and persists the result in scan history.
     *
     * @param uri Content URI pointing to the bugreport .zip file.
     * @return [BugReportAnalyzer.BugReportAnalysisResult] with SIGMA findings,
     *         legacy findings, and timeline events.
     */
    suspend fun analyzeBugReport(uri: Uri): BugReportAnalyzer.BugReportAnalysisResult {
        initRuleEngine()
        val result = bugReportAnalyzer.analyze(uri)

        // Collect app telemetry for hash enrichment — same device, same apps
        val appTelemetry = runCatching { appScanner.collectTelemetry() }.getOrDefault(emptyList())
        lastAppTelemetry = appTelemetry
        val hashByPkg = appTelemetry.filter { !it.apkHash.isNullOrEmpty() }
            .associateBy({ it.packageName }, { it.apkHash!! })

        // Persist as ScanResult so it shows in history
        val now = System.currentTimeMillis()
        val scanResult = ScanResult(
            id = now,
            timestamp = now,
            findings = result.findings,
            bugReportFindings = result.legacyFindings.map {
                "${it.severity} | ${it.category} | ${it.description}"
            },
            riskySideloadCount = 0,
            knownMalwareCount = result.findings.count {
                it.level == "critical" && it.ruleId in KNOWN_MALWARE_RULE_IDS
            }
        )
        runCatching { scanRepository.saveScan(scanResult) }
        runCatching {
            val timelineEvents = mutableListOf<com.androdr.data.model.ForensicTimelineEvent>()
            timelineEvents.addAll(result.findings.filter { it.triggered }
                .map { finding ->
                    val event = finding.toForensicTimelineEvent(scanResult, isBugreport = true)
                    if (event.apkHash.isEmpty() && event.packageName.isNotEmpty()) {
                        event.copy(apkHash = hashByPkg[event.packageName] ?: "")
                    } else event
                })
            timelineEvents.addAll(result.timeline.map { it.toForensicTimelineEvent(scanResult.id) })
            forensicTimelineEventDao.insertAll(timelineEvents)
        }

        return result
    }

    /**
     * Computes a diff between two [ScanResult] snapshots.
     *
     * @param newer The more recent scan result.
     * @param older The earlier scan result used as the baseline.
     * @return A [ScanDiff] describing what changed between the two scans.
     */
    fun computeDiff(newer: ScanResult, older: ScanResult): ScanDiff {
        val olderTriggeredIds = older.findings
            .filter { it.triggered }
            .map { it.ruleId }
            .toSet()
        val newerTriggeredIds = newer.findings
            .filter { it.triggered }
            .map { it.ruleId }
            .toSet()

        val newFindings = newer.findings.filter { it.triggered && it.ruleId !in olderTriggeredIds }
        val resolvedFindings = older.findings.filter { it.triggered && it.ruleId !in newerTriggeredIds }

        return ScanDiff(
            newFindings      = newFindings,
            resolvedFindings = resolvedFindings
        )
    }

    /**
     * Describes the delta between two consecutive scans.
     *
     * @property newFindings      Findings present in [newer] but not in [older].
     * @property resolvedFindings Findings that were in [older] but are no longer in [newer].
     */
    data class ScanDiff(
        val newFindings:      List<Finding>,
        val resolvedFindings: List<Finding>
    )

    companion object {
        private const val TAG = "ScanOrchestrator"

        /** Rule IDs that represent confirmed malware matches (IOC database hits). */
        private val KNOWN_MALWARE_RULE_IDS = setOf("androdr-001", "androdr-002")

        /** App categories treated as trusted by the known_good_app_db IOC lookup. */
        private val TRUSTED_CATEGORIES = setOf(
            com.androdr.data.model.KnownAppCategory.AOSP,
            com.androdr.data.model.KnownAppCategory.GOOGLE,
            com.androdr.data.model.KnownAppCategory.OEM,
            com.androdr.data.model.KnownAppCategory.POPULAR,
            com.androdr.data.model.KnownAppCategory.USER_APP
        )
    }
}
