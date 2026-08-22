package com.androdr.scanner

import android.content.Context
import android.net.Uri
import android.util.Log
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.toForensicTimelineEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.UNREGISTERED_IOC_LOOKUP
import com.androdr.data.repo.ScanRepository
import com.androdr.ioc.IndicatorResolver
import com.androdr.sigma.CveEvidenceProvider
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import com.androdr.sigma.SigmaCorrelationEngine
import com.androdr.sigma.SigmaRuleFeed
import com.androdr.sigma.SigmaRuleEngine
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.Collections
import java.util.zip.ZipInputStream
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
    private val intrusionLogAnalyzer: IntrusionLogAnalyzer,
    private val scanRepository: ScanRepository,
    private val dnsEventDao: DnsEventDao,
    private val forensicTimelineEventDao: ForensicTimelineEventDao,
    private val installEventEmitter: InstallEventEmitter,
    private val deviceAdminGrantEmitter: DeviceAdminGrantEmitter,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val sigmaCorrelationEngine: SigmaCorrelationEngine,
    private val indicatorResolver: IndicatorResolver,
    private val sigmaRuleFeed: SigmaRuleFeed,
    private val knownAppResolver: com.androdr.ioc.KnownAppResolver,
    private val oemPrefixResolver: com.androdr.ioc.OemPrefixResolver,
    private val brandImpersonationResolver: com.androdr.ioc.BrandImpersonationResolver,
    // #342: the orchestrator itself reads one imported ZIP's entry NAMES to
    // route it (see [sniffArtifact]); the artifact bodies are still read only
    // by the analyzers, which own their own Context.
    @ApplicationContext private val context: Context
) {

    private val initMutex = Mutex()
    private var ruleEngineInitialized = false

    /** Cached app telemetry from the most recent scan, for report export. */
    @Volatile var lastAppTelemetry: List<com.androdr.data.model.AppTelemetry> = emptyList()
        private set

    /** Cached telemetry from the most recent scan, for report export. */
    @Volatile var lastDeviceTelemetry: List<com.androdr.data.model.DeviceTelemetry> = emptyList()
        private set
    @Volatile var lastProcessTelemetry: List<com.androdr.data.model.ProcessTelemetry> = emptyList()
        private set
    @Volatile var lastFileArtifactTelemetry: List<com.androdr.data.model.FileArtifactTelemetry> = emptyList()
        private set
    @Volatile var lastAccessibilityTelemetry: List<com.androdr.data.model.AccessibilityTelemetry> = emptyList()
        private set
    @Volatile var lastReceiverTelemetry: List<com.androdr.data.model.ReceiverTelemetry> = emptyList()
        private set
    @Volatile var lastAppOpsTelemetry: List<com.androdr.data.model.AppOpsTelemetry> = emptyList()
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
        val localDevice = com.androdr.ioc.DeviceIdentity.local()
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
                    oemPrefixResolver.isOemPrefix(pkg, localDevice)
            },
            // Pure-emitter trust path (#267 / #136). Device-conditional: the closure passes localDevice
            // so an OEM store is trusted only on its ecosystem. Phase 2 migrates the rules keyed on the
            // from_trusted_store boolean onto this lookup.
            "trusted_installer_db" to { v ->
                oemPrefixResolver.isTrustedInstaller(v.toString(), localDevice)
            },
            // Brand impersonation registry (#299): word-boundary display-name
            // match + scope-host suffix match, resolver-backed (bundled seed
            // + 12h remote refresh). Backs androdr-092/093.
            "brand_name_db" to { v ->
                brandImpersonationResolver.matchesBrandName(v.toString())
            },
            "brand_domain_db" to { v ->
                brandImpersonationResolver.matchesBrandDomain(v.toString())
            }
        ))
        sigmaRuleEngine.loadBundledRules()
        // Fetch remote rules in background — non-blocking, failures are silent.
        // This is the ONE sanctioned direct sigmaRuleFeed.fetch() that does NOT
        // record feed_health (contrast IntelRefresher.refreshAll, the single
        // recorded path): it's a cold-start engine bootstrap, not a scheduled
        // refresh, and the worker/pre-scan/manual paths all record it in normal
        // operation.
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
     * Records one capability-skip entry per rule this binary cannot evaluate.
     *
     * The lookup name is FEED-CONTROLLED (it is whatever string the rule YAML
     * put after `|ioc_lookup:`, and rules are fetched from the network), and
     * this message is rendered verbatim into the exported report, so it is
     * sanitized before interpolation: non-printable / non-ASCII characters are
     * dropped so a name carrying newlines cannot forge report lines, and the
     * remainder is truncated to [MAX_LOOKUP_NAME_CHARS] so it cannot flood the
     * report. The rule id is parser-bounded (`androdr-\d+`-shaped, validated
     * upstream) and is kept raw so it stays greppable.
     */
    private fun recordRuleCapabilitySkips(errors: MutableList<ScannerFailure>) {
        sigmaRuleEngine.unevaluableRules().forEach { (ruleId, lookupName) ->
            val safeName = sanitizeLookupName(lookupName)
            errors.add(
                ScannerFailure(
                    scanner = "ruleCapability",
                    exception = UNREGISTERED_IOC_LOOKUP,
                    message = "rule $ruleId not evaluated on this build: unregistered ioc_lookup '$safeName'",
                    ruleId = ruleId
                )
            )
        }
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
        recordRuleCapabilitySkips(scannerErrors)

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
        lastDeviceTelemetry = deviceTelemetry
        lastProcessTelemetry = processTelemetry
        lastFileArtifactTelemetry = fileTelemetry
        lastAccessibilityTelemetry = accessibilityTelemetry
        lastReceiverTelemetry = receiverTelemetry
        lastAppOpsTelemetry = appOpsTelemetry

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
            it.level == "critical" && "known_malware" in it.impliesFlags
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

        // Build hash lookup from app telemetry for enrichment
        val hashByPkg = appTelemetry.filter { !it.apkHash.isNullOrEmpty() }
            .associateBy({ it.packageName }, { it.apkHash!! })
        val findingTimelineEvents = allFindings
            .filter { it.triggered }
            .map { finding ->
                val event = finding.toForensicTimelineEvent(result)
                // Enrich with APK hash from telemetry if not already set
                if (event.apkHash.isEmpty() && event.packageName.isNotEmpty()) {
                    event.copy(apkHash = hashByPkg[event.packageName] ?: "")
                } else event
            }
        // Usage stats produce timeline events directly (observational data,
        // not SIGMA telemetry). Await the deferred before entering the save
        // transaction so the whole save + finding events + usage event
        // replacement is one atomic Room write — giving Flow observers a
        // single invalidation per scan instead of three.
        val usageEvents = usageEventsDeferred.await()
        val taggedUsageEvents = usageEvents.map { it.copy(scanResultId = result.id) }

        // Correlation engine — emit install events for new packages, query a
        // lookback window of existing events, then run the correlation pass
        // INSIDE the repository's transaction once the new events have been
        // assigned real Room IDs. Running the engine on pre-insert events
        // produced signals with member_event_ids = "0,0,0" because every
        // event's default id = 0L hadn't been replaced with the autoincrement
        // value yet; the Timeline UI's expand-cluster path could not look up
        // such members. Fixed in `saveScanWithCorrelation`.
        val installEvents = runCatching {
            installEventEmitter.emitNew(result.id, appTelemetry)
        }.onFailure { Log.w(TAG, "installEventEmitter failed: ${it.message}", it) }
            .getOrDefault(emptyList())
        val adminGrantEvents = runCatching {
            deviceAdminGrantEmitter.emitNew(result.id)
        }.onFailure { Log.w(TAG, "deviceAdminGrantEmitter failed: ${it.message}", it) }
            .getOrDefault(emptyList())
        val correlationRules = sigmaRuleEngine.getCorrelationRules()
        val maxRuleWindowMs = correlationRules.maxOfOrNull { it.timespanMs } ?: 0L
        val lookbackEvents = if (maxRuleWindowMs > 0) {
            runCatching {
                forensicTimelineEventDao.getEventsSince(System.currentTimeMillis() - maxRuleWindowMs)
            }.getOrDefault(emptyList())
        } else emptyList()

        var correlationSignalCount = 0
        runCatching {
            scanRepository.saveScanWithCorrelation(
                scan = result,
                findingTimelineEvents = installEvents + adminGrantEvents + findingTimelineEvents,
                replaceUsageStatsEvents = taggedUsageEvents,
                lookbackEvents = lookbackEvents
            ) { eventsWithIds ->
                if (correlationRules.isEmpty() || eventsWithIds.isEmpty()) emptyList()
                else {
                    val bindings = sigmaRuleEngine.computeAtomBindings(eventsWithIds)
                    // Only enabled rules contribute to correlation category propagation.
                    // Including disabled rules here would let their category influence
                    // correlation classifications even though they produce no bindings.
                    val atomRulesById = sigmaRuleEngine.getEnabledRules().associateBy { it.id }
                    val signals = sigmaCorrelationEngine
                        .evaluate(correlationRules, eventsWithIds, bindings, atomRulesById)
                        .map { it.copy(scanResultId = result.id) }
                    correlationSignalCount = signals.size
                    signals
                }
            }
            Log.i(TAG, "Persisted scan ${result.id} with ${findingTimelineEvents.size} finding, " +
                "${installEvents.size} install, ${adminGrantEvents.size} admin_grant, " +
                "$correlationSignalCount signal, " +
                "${taggedUsageEvents.size} usage events (single transaction)")
        }.onFailure { Log.e(TAG, "Failed to persist scan results", it) }

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
        recordRuleCapabilitySkips(bugReportScannerErrors)
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
            bugReportFindings = emptyList(),
            riskySideloadCount = 0,
            knownMalwareCount = result.findings.count {
                it.level == "critical" && "known_malware" in it.impliesFlags
            },
            scannerErrors = bugReportScannerErrors
        )
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
            .filter { it.startTimestamp > 0L && it.packageName.isNotEmpty() }
            .mapTo(HashSet()) { it.packageName to it.startTimestamp }
        val rawEvents = result.timeline
            .filterNot { raw ->
                raw.packageName != null &&
                    (raw.packageName to raw.timestamp) in coveredByFinding
            }
            .map { it.toForensicTimelineEvent(scanResult.id) }
        // Phase 3: bug-report module-produced ForensicTimelineEvents (e.g.
        // InstallTimeModule's package_install rows). These already carry
        // isFromBugreport = true and scan-independent shape; stamp them
        // with the scanResultId for history association.
        val moduleForensicEvents = result.forensicEvents.map {
            it.copy(scanResultId = scanResult.id)
        }
        val baseBugReportEvents = findingEvents + rawEvents + moduleForensicEvents

        // Correlation engine runs inside the repository transaction AFTER the
        // raw events get their Room autoincrement IDs. Before this change, the
        // bug-report path evaluated correlation on pre-insert events whose
        // `id` was still the default 0L, so every signal's member_event_ids
        // serialized as "0,0,0" and the Timeline UI couldn't expand clusters.
        // Bug reports are snapshots — no historical lookback query.
        val brCorrelationRules = sigmaRuleEngine.getCorrelationRules()
        runCatching {
            scanRepository.saveScanWithCorrelation(
                scan = scanResult,
                findingTimelineEvents = baseBugReportEvents,
                replaceUsageStatsEvents = null,
                lookbackEvents = emptyList()
            ) { eventsWithIds ->
                if (brCorrelationRules.isEmpty() || eventsWithIds.isEmpty()) emptyList()
                else {
                    val bindings = sigmaRuleEngine.computeAtomBindings(eventsWithIds)
                    val atomRulesById = sigmaRuleEngine.getEnabledRules().associateBy { it.id }
                    sigmaCorrelationEngine.evaluate(brCorrelationRules, eventsWithIds, bindings, atomRulesById)
                        .map { it.copy(scanResultId = scanResult.id) }
                }
            }
        }.onFailure { Log.e(TAG, "Failed to persist bug-report scan results", it) }

        return result
    }

    /** Thrown by [analyzeArtifact] when the imported ZIP is neither supported artifact. */
    class UnrecognizedArtifactException : Exception(
        "Not a recognized artifact: expected a bug report ZIP (dumpstate) or an " +
            "Advanced Protection intrusion log export (per-day YYYY-MM-DD.txt files)."
    )

    /** Result of [analyzeArtifact], carrying whichever analysis actually ran. */
    sealed interface ArtifactAnalysis {
        data class BugReport(val result: BugReportAnalyzer.BugReportAnalysisResult) : ArtifactAnalysis
        data class IntrusionLog(val result: IntrusionLogAnalysisResult) : ArtifactAnalysis
    }

    /** #342: single import entry point — sniff the ZIP, route to the right analyzer. */
    suspend fun analyzeArtifact(uri: Uri): ArtifactAnalysis = when (sniffArtifact(uri)) {
        ArtifactType.BUG_REPORT -> ArtifactAnalysis.BugReport(analyzeBugReport(uri))
        ArtifactType.INTRUSION_LOG -> ArtifactAnalysis.IntrusionLog(analyzeIntrusionLog(uri))
        ArtifactType.UNRECOGNIZED -> throw UnrecognizedArtifactException()
    }

    /**
     * Classifies an imported ZIP by its entry names alone (#342 spec §4.1) —
     * entry bodies are never read here, so this stays cheap on a multi-hundred-MB
     * bug report. The analyzer then re-opens the URI to read the content.
     */
    private suspend fun sniffArtifact(uri: Uri): ArtifactType = withContext(Dispatchers.IO) {
        val stream = context.contentResolver.openInputStream(uri)
            ?: return@withContext ArtifactType.UNRECOGNIZED
        stream.use { s ->
            ZipInputStream(s.buffered()).use { zip ->
                val names = sequence {
                    var entry = zip.nextEntry
                    while (entry != null) {
                        if (!entry.isDirectory) yield(entry.name)
                        try { zip.closeEntry() } catch (_: Exception) { /* ignore */ }
                        entry = try { zip.nextEntry } catch (_: Exception) { null }
                    }
                }
                ArtifactSniffer.classify(names)
            }
        }
    }

    /**
     * #342: analyze an Advanced Protection Intrusion Logging export and persist
     * it. Replace-on-reimport: each import first deletes the previous import's
     * rows by source (spec §4.2). Rules saw the COMPLETE stream inside the
     * analyzer; only timeline persistence is capped (spec §7).
     */
    suspend fun analyzeIntrusionLog(uri: Uri): IntrusionLogAnalysisResult {
        initRuleEngine()
        val result = intrusionLogAnalyzer.analyze(uri)

        val now = System.currentTimeMillis()
        val scanResult = ScanResult(
            id = now,
            timestamp = now,
            findings = result.findings,
            bugReportFindings = emptyList(),
            riskySideloadCount = 0,
            knownMalwareCount = result.findings.count {
                it.level == "critical" && "known_malware" in it.impliesFlags
            },
            scannerErrors = emptyList()
        )
        val allEvents = buildIntrusionLogTimelineEvents(result, scanResult)

        // Replace-on-reimport, then persist with correlation (same transaction
        // shape as the bug-report path). The two deletes run before the save so
        // a re-import of the same (or a corrected) export replaces the previous
        // import's rows instead of stacking a second copy of every event.
        forensicTimelineEventDao.deleteBySource("intrusion_log")
        forensicTimelineEventDao.deleteBySource("intrusion_log_analysis")
        val corrRules = sigmaRuleEngine.getCorrelationRules()
        runCatching {
            scanRepository.saveScanWithCorrelation(
                scan = scanResult,
                findingTimelineEvents = allEvents,
                replaceUsageStatsEvents = null,
                lookbackEvents = emptyList()
            ) { eventsWithIds ->
                if (corrRules.isEmpty() || eventsWithIds.isEmpty()) emptyList()
                else {
                    val bindings = sigmaRuleEngine.computeAtomBindings(eventsWithIds)
                    val atomRulesById = sigmaRuleEngine.getEnabledRules().associateBy { it.id }
                    sigmaCorrelationEngine.evaluate(corrRules, eventsWithIds, bindings, atomRulesById)
                        .map { it.copy(scanResultId = scanResult.id) }
                }
            }
            Log.i(TAG, "Persisted intrusion-log import ${scanResult.id} with ${allEvents.size} events")
        }.onFailure { Log.e(TAG, "Failed to persist intrusion log import", it) }

        return result
    }

    /**
     * Builds the timeline rows for one intrusion-log import: one row per
     * triggered finding (`source = "intrusion_log_analysis"`) followed by the
     * raw imported evidence (`source = "intrusion_log"`).
     *
     * Persistence caps (spec §7): security events are uncapped — they are the
     * rarest and highest-signal records — while DNS and connect events are kept
     * newest-first up to [DNS_PERSIST_CAP] / [CONNECT_PERSIST_CAP]. Detection is
     * unaffected: [IntrusionLogAnalyzer] already evaluated the rules over the
     * COMPLETE parsed stream, so a capped event can still have produced a
     * finding row here.
     */
    private fun buildIntrusionLogTimelineEvents(
        result: IntrusionLogAnalysisResult,
        scanResult: ScanResult
    ): List<ForensicTimelineEvent> {
        val findingEvents = result.findings.filter { it.triggered }.map { finding ->
            finding.toForensicTimelineEvent(scanResult, isBugreport = true).copy(
                source = "intrusion_log_analysis",
                telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT,
                // The network/security field maps carry "timestamp" and the
                // evaluator copies scalar record fields into matchContext as
                // strings, so a finding inherits its own event's time. DNS
                // records carry no timestamp field — those fall back to 0L,
                // which the Timeline renders as "Unknown".
                startTimestamp = finding.matchContext["timestamp"]?.toLongOrNull()
                    ?.takeIf { it > 0L } ?: 0L
            )
        }
        val cappedDns = result.dnsEvents
            .sortedByDescending { it.event.timestamp }
            .take(DNS_PERSIST_CAP)
        val cappedNet = result.networkEvents
            .sortedByDescending { it.timestamp }
            .take(CONNECT_PERSIST_CAP)
        return findingEvents +
            cappedDns.map { it.toForensicTimelineEvent(scanResult.id) } +
            cappedNet.map { it.toForensicTimelineEvent(scanResult.id) } +
            result.securityEvents.map { it.toForensicTimelineEvent(scanResult.id) }
    }

    /**
     * Computes a diff between two [ScanResult] snapshots.
     *
     * PURE: the answer depends only on the two arguments. The set of rules that
     * could not be evaluated is read from [newer]'s own persisted
     * capability-skip entries ([UNREGISTERED_IOC_LOOKUP] failures, each
     * carrying its [ScannerFailure.ruleId]) rather than from the live engine,
     * so a diff computed at cold start — before any scan has run in this
     * process, i.e. before the engine knows its own lookup registrations — is
     * identical to one computed mid-session, and a History diff between two old
     * scans reflects what *those* scans could evaluate rather than what this
     * process can evaluate right now.
     *
     * A rule that triggered in [older] but was skipped during [newer] — rather
     * than genuinely un-triggered — must NOT surface as "resolved": rendering a
     * skipped CRITICAL as resolved is affirmative false reassurance, worse than
     * a silent miss.
     *
     * Backward-compatibility limit: capability-skip rows persisted before
     * [ScannerFailure.ruleId] existed carry no rule id, so they contribute
     * nothing to the skip set and a rule skipped in such a scan can still read
     * as resolved. Only scans written by an older binary are affected.
     *
     * @param newer The more recent scan result.
     * @param older The earlier scan result used as the baseline.
     * @return A [ScanDiff] describing what changed between the two scans.
     */
    fun computeDiff(
        newer: ScanResult,
        older: ScanResult
    ): ScanDiff {
        val skippedRuleIds = newer.scannerErrors
            .filter { it.exception == UNREGISTERED_IOC_LOOKUP }
            .mapNotNull { it.ruleId }
            .toSet()
        val olderTriggeredIds = older.findings
            .filter { it.triggered }
            .map { it.ruleId }
            .toSet()
        val newerTriggeredIds = newer.findings
            .filter { it.triggered }
            .map { it.ruleId }
            .toSet()

        val newFindings = newer.findings.filter { it.triggered && it.ruleId !in olderTriggeredIds }
        val resolvedFindings = older.findings.filter {
            it.triggered && it.ruleId !in newerTriggeredIds && it.ruleId !in skippedRuleIds
        }

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
         * Cap on the feed-controlled `ioc_lookup` name echoed into a
         * capability-skip message. Real names are short snake_case identifiers
         * (`trusted_installer_db` is 20 chars), so this is generous while still
         * bounding a hostile rule's contribution to one report line.
         */
        private const val MAX_LOOKUP_NAME_CHARS = 64

        /**
         * Reduces a feed-controlled lookup name to printable ASCII, then caps
         * its length. Printable-ASCII-only is not cosmetic: the report is
         * strictly ASCII (enforced by ReportFormatterTest) and is rendered
         * line-per-entry, so a name containing CR/LF could otherwise inject
         * lines that read as additional report content.
         */
        private fun sanitizeLookupName(name: String): String =
            name.filter { it in ' '..'~' }.take(MAX_LOOKUP_NAME_CHARS)

        /**
         * Number of parallel scanners tracked by the progress indicator.
         * Keep in sync with the scanners launched in [runFullScanInner] —
         * adding or removing a scanner requires updating this constant so
         * the progress bar fills to 100%.
         */
        private const val SCANNER_COUNT = 8

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

        /** #342 spec §7: timeline persistence caps; rules always see the full stream. */
        const val DNS_PERSIST_CAP = 10_000
        const val CONNECT_PERSIST_CAP = 5_000

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
