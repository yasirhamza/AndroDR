package com.androdr.scanner

import android.net.Uri
import android.util.Log
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.repo.ScanRepository
import com.androdr.ioc.IndicatorResolver
import com.androdr.sigma.CveEvidenceProvider
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.SigmaRuleFeed
import com.androdr.sigma.SigmaRuleEngine
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.Collections
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

    /**
     * Wall-clock timestamp of the last successful [AppScanner.collectTelemetry]
     * call, used by [analyzeBugReport] to decide whether the cached
     * [lastAppTelemetry] is fresh enough to reuse for APK-hash enrichment.
     * Initialized to 0 so a brand-new process always does a fresh scan on
     * first bug report analysis.
     */
    @Volatile private var lastAppTelemetryTimestamp: Long = 0L

    /**
     * Live progress for the currently-running scan (or [ScanProgress.Idle]
     * when no scan is active). The Dashboard UI observes this to render the
     * per-phase progress indicator and stage counter.
     */
    private val _scanProgress = MutableStateFlow<ScanProgress>(ScanProgress.Idle)
    val scanProgress: StateFlow<ScanProgress> = _scanProgress.asStateFlow()

    /**
     * Wraps a single scanner's telemetry-collection call with:
     *   1. **Per-scanner error isolation.** Any exception (other than
     *      [CancellationException]) is caught, logged, and recorded in
     *      [errors] so the final [ScanResult] can tell the UI which scanners
     *      failed. The other scanners continue running — one failure does not
     *      zero out the whole scan.
     *   2. **Cancellation pass-through.** [CancellationException] is
     *      re-thrown so coroutine cancellation still works end-to-end.
     *   3. **Progress counter increment.** On completion (success or
     *      failure) the scan-progress StateFlow is advanced by one. We count
     *      failed scanners as "completed" from the progress perspective
     *      because the user cares about wall-clock progress, not success
     *      rate — the failures are surfaced separately in the scan result.
     *
     * Silently swallowing scanner exceptions (the previous behavior) was a
     * detection-evasion hazard: a malware sample that crashed any one scanner
     * would cause that scanner's category of findings to disappear, yielding
     * an apparently-clean scan result indistinguishable from a real clean.
     */
    @Suppress("TooGenericExceptionCaught")
    private suspend fun <T> trackScanner(
        name: String,
        errors: MutableList<ScannerFailure>,
        default: T,
        block: suspend () -> T
    ): T {
        return try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "$name failed", e)
            errors.add(
                ScannerFailure(
                    scanner = name,
                    exception = e::class.simpleName ?: "Exception",
                    message = e.message
                )
            )
            default
        } finally {
            _scanProgress.update { current ->
                if (current is ScanProgress.Running) {
                    current.copy(completedScanners = current.completedScanners + 1)
                } else {
                    current
                }
            }
        }
    }

    /** Launches a tracked scanner call inside the enclosing coroutineScope. */
    private fun <T> CoroutineScope.trackedAsync(
        name: String,
        errors: MutableList<ScannerFailure>,
        default: T,
        block: suspend () -> T
    ): Deferred<T> = async { trackScanner(name, errors, default, block) }

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
    @Suppress("LongMethod", "TooGenericExceptionCaught")
    // Two-phase scan: telemetry collection + SIGMA rule evaluation. Wrapped
    // in try/finally so progress is always reset even if something above the
    // scanner-tracker level throws (e.g. SIGMA rule engine init failure).
    suspend fun runFullScan(): ScanResult = try {
        runFullScanInner()
    } finally {
        _scanProgress.value = ScanProgress.Idle
    }

    @Suppress("LongMethod") // Linear two-phase scan body kept intact for readability
    private suspend fun runFullScanInner(): ScanResult = coroutineScope {
        initRuleEngine()

        // scannerErrors is written from inside parallel async blocks, so it
        // needs a synchronized wrapper. Using the Collections.synchronizedList
        // wrapper gives us mutex semantics with no extra boilerplate.
        val scannerErrors: MutableList<ScannerFailure> =
            Collections.synchronizedList(mutableListOf())

        // Initialize progress for phase 1 — 8 parallel scanners to track.
        _scanProgress.value = ScanProgress.Running(
            phase = ScanProgress.Running.Phase.COLLECTING_TELEMETRY,
            completedScanners = 0,
            totalScanners = SCANNER_COUNT
        )

        // Phase 1: Collect telemetry (no detection logic)
        val appTelemetryDeferred = trackedAsync("appScanner", scannerErrors, emptyList()) {
            appScanner.collectTelemetry()
        }
        val deviceTelemetryDeferred = trackedAsync("deviceAuditor", scannerErrors, emptyList()) {
            deviceAuditor.collectTelemetry()
        }
        val processTelemetryDeferred = trackedAsync("processScanner", scannerErrors, emptyList()) {
            processScanner.collectTelemetry()
        }
        val fileTelemetryDeferred = trackedAsync("fileArtifactScanner", scannerErrors, emptyList()) {
            fileArtifactScanner.collectTelemetry()
        }
        val accessibilityTelemetryDeferred =
            trackedAsync("accessibilityAuditScanner", scannerErrors, emptyList()) {
                accessibilityAuditScanner.collectTelemetry()
            }
        val receiverTelemetryDeferred =
            trackedAsync("receiverAuditScanner", scannerErrors, emptyList()) {
                receiverAuditScanner.collectTelemetry()
            }
        val appOpsTelemetryDeferred = trackedAsync("appOpsScanner", scannerErrors, emptyList()) {
            appOpsScanner.collectTelemetry()
        }
        val usageEventsDeferred = trackedAsync("usageStatsScanner", scannerErrors, emptyList()) {
            usageStatsScanner.collectTimelineEvents()
        }

        val appTelemetry = appTelemetryDeferred.await()
        lastAppTelemetry = appTelemetry // cache for report export
        // Stamp the cache freshness so analyzeBugReport() can decide
        // whether to reuse this telemetry or do its own fresh scan.
        if (appTelemetry.isNotEmpty()) {
            lastAppTelemetryTimestamp = System.currentTimeMillis()
        }
        val deviceTelemetry = deviceTelemetryDeferred.await()
        val processTelemetry = processTelemetryDeferred.await()
        val fileTelemetry = fileTelemetryDeferred.await()
        val accessibilityTelemetry = accessibilityTelemetryDeferred.await()
        val receiverTelemetry = receiverTelemetryDeferred.await()
        val appOpsTelemetry = appOpsTelemetryDeferred.await()

        // Phase 2: SIGMA rule evaluation — all detection via rules
        _scanProgress.value = ScanProgress.Running(
            phase = ScanProgress.Running.Phase.EVALUATING_RULES,
            completedScanners = SCANNER_COUNT,
            totalScanners = SCANNER_COUNT
        )
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

        // Snapshot scanner errors before building the result — after this point
        // no more scanner-phase work can add to the list.
        val snapshottedErrors: List<ScannerFailure> =
            synchronized(scannerErrors) { scannerErrors.toList() }

        _scanProgress.value = ScanProgress.Running(
            phase = ScanProgress.Running.Phase.SAVING_RESULTS,
            completedScanners = SCANNER_COUNT,
            totalScanners = SCANNER_COUNT
        )

        val now = System.currentTimeMillis()
        val result = ScanResult(
            id                 = now,
            timestamp          = now,
            findings           = allFindings,
            bugReportFindings  = emptyList(),
            riskySideloadCount = sideloadedCount,
            knownMalwareCount  = malwareCount,
            scannerErrors      = snapshottedErrors
        )

        if (snapshottedErrors.isNotEmpty()) {
            Log.w(TAG, "Scan completed with ${snapshottedErrors.size} scanner failures: " +
                snapshottedErrors.joinToString { "${it.scanner}(${it.exception})" })
        }

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

        // Progress is reset to Idle by the outer runFullScan() in its
        // `finally` block, which also handles the exception path.
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
    @Suppress("TooGenericExceptionCaught", "LongMethod")
    suspend fun analyzeBugReport(uri: Uri): BugReportAnalyzer.BugReportAnalysisResult {
        initRuleEngine()
        val result = bugReportAnalyzer.analyze(uri)

        // Collect app telemetry for hash enrichment — same device, same apps.
        //
        // Two things combined here:
        //  1. AppTelemetry cache reuse: if a recent runtime scan populated
        //     `lastAppTelemetry` within the freshness window, reuse it
        //     instead of re-running AppScanner (which takes ~14s on a real
        //     device with ~500 installed packages).
        //  2. Proper error handling: on cache miss, a cancellation must
        //     still propagate, and any other exception from collectTelemetry
        //     is recorded as a scanner failure on the persisted ScanResult
        //     so the Dashboard partial-scan banner fires.
        val bugReportScannerErrors = mutableListOf<ScannerFailure>()
        val cacheAgeMs = System.currentTimeMillis() - lastAppTelemetryTimestamp
        val appTelemetry: List<com.androdr.data.model.AppTelemetry> =
            if (lastAppTelemetryTimestamp > 0L &&
                cacheAgeMs <= APP_TELEMETRY_CACHE_MAX_AGE_MS &&
                lastAppTelemetry.isNotEmpty()
            ) {
                Log.i(TAG, "analyzeBugReport: reusing cached app telemetry " +
                    "(${lastAppTelemetry.size} entries, ${cacheAgeMs}ms old)")
                lastAppTelemetry
            } else {
                try {
                    appScanner.collectTelemetry().also { fresh ->
                        if (fresh.isNotEmpty()) {
                            lastAppTelemetry = fresh
                            lastAppTelemetryTimestamp = System.currentTimeMillis()
                        }
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e(TAG, "appScanner failed during bug-report enrichment", e)
                    bugReportScannerErrors.add(
                        ScannerFailure(
                            scanner = "appScanner",
                            exception = e::class.simpleName ?: "Exception",
                            message = e.message
                        )
                    )
                    emptyList()
                }
            }
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
            },
            scannerErrors = bugReportScannerErrors
        )
        runCatching { scanRepository.saveScan(scanResult) }
        runCatching {
            val timelineEvents = mutableListOf<com.androdr.data.model.ForensicTimelineEvent>()

            // Phase 1: finding-derived events. Each triggered finding becomes
            // one ForensicTimelineEvent. Bug-report findings may inherit a
            // real `event_time_ms` from their underlying telemetry record
            // (see TimelineAdapter.Finding.toForensicTimelineEvent) — so a
            // "Camera Access" finding now shows up at the actual time the
            // AppOps access was recorded, not at 0L / "Unknown".
            val findingEvents = result.findings.filter { it.triggered }
                .map { finding ->
                    val event = finding.toForensicTimelineEvent(scanResult, isBugreport = true)
                    if (event.apkHash.isEmpty() && event.packageName.isNotEmpty()) {
                        event.copy(apkHash = hashByPkg[event.packageName] ?: "")
                    } else event
                }
            timelineEvents.addAll(findingEvents)

            // Phase 2: raw module-produced timeline events, **deduplicated**
            // against finding-derived events that inherited the same
            // (packageName, timestamp) tuple. Without this filter the
            // Timeline would show a "Camera Access" finding row right next
            // to a raw "com.X used CAMERA at ..." row with the identical
            // time — two rows describing the same underlying evidence,
            // which reads as a duplicate to the user. Raw events for
            // unmatched AppOps records (packages whose dangerous-op usage
            // didn't trigger any SIGMA rule) still appear as before.
            val coveredByFinding = findingEvents
                .filter { it.timestamp > 0L && it.packageName.isNotEmpty() }
                .mapTo(HashSet()) { it.packageName to it.timestamp }
            val rawEvents = result.timeline
                .filterNot { raw ->
                    raw.packageName != null &&
                        (raw.packageName to raw.timestamp) in coveredByFinding
                }
                .map { it.toForensicTimelineEvent(scanResult.id) }
            timelineEvents.addAll(rawEvents)

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

        /**
         * Number of parallel scanners tracked by the progress indicator.
         * Keep in sync with the scanners launched in [runFullScanInner] —
         * adding or removing a scanner requires updating this constant so
         * the progress bar fills to 100%.
         */
        private const val SCANNER_COUNT = 8

        /** Rule IDs that represent confirmed malware matches (IOC database hits). */
        private val KNOWN_MALWARE_RULE_IDS = setOf("androdr-001", "androdr-002")

        /**
         * Maximum age of the cached app telemetry that [analyzeBugReport]
         * will reuse for bug-report APK-hash enrichment instead of running
         * a fresh [AppScanner.collectTelemetry] call. Chosen to cover the
         * typical "Run Scan → immediately analyze a bug report" flow
         * without paying the ~14s AppScanner cost twice on real devices,
         * but short enough that stale caches don't mask recent app
         * installations or updates.
         */
        private const val APP_TELEMETRY_CACHE_MAX_AGE_MS = 5L * 60_000L // 5 minutes

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
