package com.androdr.scanner

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.annotation.VisibleForTesting
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.Indicator
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.UNREGISTERED_IOC_LOOKUP
import com.androdr.data.store.DecodedRecord
import com.androdr.data.store.TelemetryReader
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.TimelineRowDeleter
import com.androdr.ioc.IndicatorResolver
import com.androdr.network.DnsVpnService
import com.androdr.sigma.CveEvidenceProvider
import com.androdr.sigma.EvidenceProvider
import com.androdr.sigma.Finding
import com.androdr.sigma.IocMatchEvidenceProvider
import com.androdr.sigma.LiveRecordBuilders
import com.androdr.sigma.RuleCoverage
import com.androdr.sigma.SigmaCorrelationEngine
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import com.androdr.util.reportSafe
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.Collections
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Orchestrates all scanning operations. Every writer — the live scan, the bug-report import and the
 * intrusion-log import — runs inside [ScanLock.withWriter] and evaluates and stores its telemetry
 * only through one [ChunkedScanWriter] session (spec §4.1, §5.2): records are appended chunk by
 * chunk, and every Timeline row is written in the session's single finishing transaction. A failed
 * writer aborts its session, so nothing of it is ever visible (#342 B1).
 */
@Singleton
@Suppress("LongParameterList") // All parameters are Hilt-injected dependencies
class ScanOrchestrator @Inject constructor(
    private val collector: LiveScanCollector,
    private val appScanner: AppScanner,
    private val bugReportAnalyzer: BugReportAnalyzer,
    private val intrusionLogAnalyzer: IntrusionLogAnalyzer,
    private val writer: ChunkedScanWriter,
    private val scanLock: ScanLock,
    private val forensicTimelineEventDao: ForensicTimelineEventDao,
    private val timelineRows: TimelineRowDeleter,
    private val installEventEmitter: InstallEventEmitter,
    private val deviceAdminGrantEmitter: DeviceAdminGrantEmitter,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val sigmaCorrelationEngine: SigmaCorrelationEngine,
    private val indicatorResolver: IndicatorResolver,
    private val sigmaRuleFeed: SigmaRuleFeed,
    private val knownAppResolver: com.androdr.ioc.KnownAppResolver,
    private val oemPrefixResolver: com.androdr.ioc.OemPrefixResolver,
    private val brandImpersonationResolver: com.androdr.ioc.BrandImpersonationResolver,
    private val telemetryReader: TelemetryReader,
    // #342: the orchestrator itself reads one imported ZIP's entry NAMES to
    // route it (see [sniffArtifact]); the artifact bodies are still read only
    // by the analyzers, which own their own Context.
    @ApplicationContext private val context: Context
) {

    private val initMutex = Mutex()
    private var ruleEngineInitialized = false

    /**
     * Live progress for the currently-running scan (or [ScanProgress.Idle]
     * when no scan is active). The Dashboard UI observes this to render the
     * per-phase progress indicator and stage counter.
     */
    private val _scanProgress = MutableStateFlow<ScanProgress>(ScanProgress.Idle)
    val scanProgress: StateFlow<ScanProgress> = _scanProgress.asStateFlow()

    private suspend fun initRuleEngine() = initMutex.withLock {
        if (ruleEngineInitialized) return@withLock
        val localDevice = com.androdr.ioc.DeviceIdentity.local()
        sigmaRuleEngine.setIocLookups(mapOf(
            "package_ioc_db" to { v -> indicatorResolver.isKnownBadPackage(v.toString()) != null },
            "cert_hash_ioc_db" to { v -> indicatorResolver.isKnownBadCert(v.toString()) != null },
            // Bundle fallback: a bundled domain still matches before the first feed sync (cold start).
            "domain_ioc_db" to { v -> indicatorResolver.isKnownBadDomainWithBundle(v.toString()) != null },
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
                sigmaRuleEngine.setRemoteRules(remoteRules, sigmaRuleFeed.lastRejected)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Remote SIGMA rule fetch failed: ${e.message}")
        }
        val providers: Map<String, EvidenceProvider> =
            buildEvidenceProviders(sigmaRuleEngine.getRules()) { db, value -> iocRow(indicatorResolver, db, value) }
        check(providers.keys == REGISTERED_EVIDENCE_TYPES) {
            "providers ${providers.keys} != $REGISTERED_EVIDENCE_TYPES"
        }
        sigmaRuleEngine.setEvidenceProviders(providers)
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
     * remainder is truncated to [MAX_REPORT_TEXT_CHARS] so it cannot flood the
     * report. The rule id is parser-bounded (`androdr-\d+`-shaped, validated
     * upstream) and is kept raw so it stays greppable.
     */
    private fun recordRuleCapabilitySkips(errors: MutableList<ScannerFailure>) {
        // #288: remote rules this build verified but could not read.
        errors.addAll(
            RuleCoverage.rejectedRuleSkips(
                sigmaRuleEngine.rejectedRemoteRules(), sigmaRuleEngine.getEnabledRules().mapTo(HashSet()) { it.id },
            )
        )
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
     * Runs a full device scan: the scanners collect telemetry in parallel ([LiveScanCollector]),
     * then every service is appended to one live writer session, which evaluates and stores it.
     * Progress is always reset, even when something above the scanner level throws.
     */
    suspend fun runFullScan(): ScanResult = try {
        // Callers launch from a ViewModel (Main); rule loading, record building and the session are
        // CPU work, so they run on Default (A8 D2). The lock is a Mutex, taken outside any transaction.
        scanLock.withWriter { withContext(Dispatchers.Default) { runFullScanInner() } }
    } finally {
        _scanProgress.value = ScanProgress.Idle
    }

    @Suppress("TooGenericExceptionCaught") // a failed write must not crash the caller (abort, then report)
    private suspend fun runFullScanInner(): ScanResult {
        initRuleEngine()
        // Written from inside the parallel collectors, so it needs a synchronized wrapper.
        val errors: MutableList<ScannerFailure> = Collections.synchronizedList(mutableListOf())
        recordRuleCapabilitySkips(errors)
        errors.addAll(visibilityGapsOrFailure({ indicatorResolver.feedCoverage() }, DnsVpnService.isRunning.value))

        progress(ScanProgress.Running.Phase.COLLECTING_TELEMETRY, 0)
        val telemetry = collector.collect(errors) {
            _scanProgress.update { p ->
                if (p is ScanProgress.Running) p.copy(completedScanners = p.completedScanners + 1) else p
            }
        }
        progress(ScanProgress.Running.Phase.EVALUATING_RULES, LiveScanCollector.SCANNER_COUNT)
        // #366: the engine judges only the paths it could read. What went unread is
        // declared, so the report states the limit instead of reading like a clean check.
        errors.addAll(RuleCoverage.unreadableArtifactSkips(sigmaRuleEngine.getEnabledRules(), telemetry.files))

        val now = System.currentTimeMillis()
        val scan = ScanResult(
            id = now, timestamp = now, findings = emptyList(), bugReportFindings = emptyList(),
            riskySideloadCount = 0, knownMalwareCount = 0,
        )
        val hooks = LiveScanHooks(
            scan, sigmaRuleEngine, sigmaCorrelationEngine, forensicTimelineEventDao, timelineRows,
            hashByPackage(telemetry.apps), detectedChanges(scan.id, telemetry.apps),
            sigmaRuleEngine.getCorrelationRules().maxOfOrNull { it.timespanMs } ?: 0L,
        )
        hooks.readLookback()
        hooks.errors.addAll(synchronized(errors) { errors.toList() })
        // A failed write keeps nothing (the session is aborted), but the in-memory findings are
        // still returned with the writer failure, so the Dashboard never reads as clean.
        val recover = { session: ChunkedScanWriter.Session, t: Throwable ->
            Log.e(TAG, "Failed to persist scan results", t)
            val kept = session.keptScan()
            kept.copy(scannerErrors = kept.scannerErrors + writerFailure(t))
        }
        return try {
            writer.inSession(scan, liveEvents = true, hooks, recover) { session ->
                appendLive(session, hooks, telemetry, now, indicatorResolver)
                progress(ScanProgress.Running.Phase.SAVING_RESULTS, LiveScanCollector.SCANNER_COUNT)
                session.finish().scan
            }.also { Log.i(TAG, "Scan ${it.id} complete — ${it.findings.size} findings, " +
                "${it.scannerErrors.size} scanner entries") }
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            // The session could not even be opened: nothing was evaluated or kept.
            Log.e(TAG, "Failed to open the scan's writer session", t)
            scan.copy(scannerErrors = synchronized(errors) { errors.toList() } + writerFailure(t))
        }
    }

    /** Detected-change rows for this scan: first-seen installs and device-admin grants. */
    private suspend fun detectedChanges(scanId: Long, apps: List<AppTelemetry>) =
        runCatching { installEventEmitter.emitNew(scanId, apps) }
            .onFailure { Log.w(TAG, "installEventEmitter failed: ${it.message}", it) }.getOrDefault(emptyList()) +
            runCatching { deviceAdminGrantEmitter.emitNew(scanId) }
                .onFailure { Log.w(TAG, "deviceAdminGrantEmitter failed: ${it.message}", it) }.getOrDefault(emptyList())

    private fun progress(phase: ScanProgress.Running.Phase, completed: Int) {
        _scanProgress.value = ScanProgress.Running(phase, completed, LiveScanCollector.SCANNER_COUNT)
    }

    /**
     * Analyzes a bug report and persists it in scan history through one import session: every
     * module's telemetry — generic field maps and typed records — is evaluated and stored (B1).
     *
     * @return the analysis with the session's findings; throws [BugReportPersistException] when the
     *   import could not be saved (nothing of it is kept).
     */
    @Suppress("TooGenericExceptionCaught")
    suspend fun analyzeBugReport(uri: Uri): BugReportAnalyzer.BugReportAnalysisResult =
        // CPU work (rules, records, session) off the caller's Main; the lock is outside any transaction (A8 D2).
        scanLock.withWriter { withContext(Dispatchers.Default) {
        initRuleEngine()
        val result = bugReportAnalyzer.analyze(uri)
        // Capability skips and enrichment failures are recorded on the persisted scan, so the
        // Dashboard partial-scan banner fires.
        val errors = mutableListOf<ScannerFailure>()
        recordRuleCapabilitySkips(errors)
        val apkHashes = enrichmentHashes(errors)
        val now = System.currentTimeMillis()
        val scan = ScanResult(
            id = now, timestamp = now, findings = emptyList(), bugReportFindings = emptyList(),
            riskySideloadCount = 0, knownMalwareCount = 0,
            // #356: an imported artifact is not a scan of the device in front of
            // the user; History labels it from this field.
            source = TelemetrySource.BUGREPORT_IMPORT,
        )
        val hooks = BugReportHooks(scan, sigmaRuleEngine, sigmaCorrelationEngine, apkHashes,
            result.timeline, result.forensicEvents)
        hooks.errors.addAll(errors)
        val written = try {
            writer.inSession(scan, liveEvents = false, hooks) { session ->
                appendBugReport(session, result, now)
                requireSaved(session.finish())
            }
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to persist bug-report scan results", t)
            throw BugReportPersistException(t)
        }
        result.copy(findings = written.scan.findings, write = written)
    } }

    /**
     * APK hashes by package for bug-report enrichment -- same device, same apps. The newest stored
     * live scan's app records are reused when they were captured within
     * [TelemetryReader.APP_ENRICHMENT_MAX_AGE_MS] (AppScanner takes ~14 s with ~500 packages);
     * otherwise a fresh collection runs. A cancellation propagates; any other failure is recorded in
     * [errors] and enrichment is skipped. Enrichment data is never stored under an import.
     */
    @Suppress("TooGenericExceptionCaught")
    private suspend fun enrichmentHashes(errors: MutableList<ScannerFailure>): Map<String, String> {
        val stored = try {
            telemetryReader.latestLive(LiveRecordBuilders.APP_SCANNER, TelemetryReader.APP_ENRICHMENT_MAX_AGE_MS)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "stored app records unreadable; collecting fresh for enrichment", e)
            null
        }
        if (!stored.isNullOrEmpty()) {
            Log.i(TAG, "analyzeBugReport: reusing the latest live scan's ${stored.size} stored app records")
            return storedHashByPackage(stored)
        }
        return try {
            hashByPackage(appScanner.collectTelemetry())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "appScanner failed during bug-report enrichment", e)
            errors.add(ScannerFailure(scanner = "appScanner", exception = e::class.simpleName ?: "Exception",
                message = e.message))
            emptyMap()
        }
    }

    /** Thrown by [analyzeArtifact] when the imported ZIP is neither supported artifact. */
    class UnrecognizedArtifactException : Exception(
        "Not a recognized artifact: expected a bug report ZIP (dumpstate) or an " +
            "Advanced Protection intrusion log export (per-day YYYY-MM-DD.txt files)."
    )

    /**
     * Thrown by [analyzeIntrusionLog] when the analysis succeeded but persisting
     * it failed (#342 B1). The user-visible message is intentionally honest: the
     * import was analyzed but not saved, so nothing was imported. Carries the
     * underlying persistence [cause] for logs/diagnostics.
     */
    class IntrusionLogPersistException(cause: Throwable) : Exception(
        "Intrusion log analyzed, but saving it failed — nothing was imported.",
        cause
    )

    /** Like [IntrusionLogPersistException], for a bug report whose import session failed. */
    class BugReportPersistException(cause: Throwable) : Exception(
        "Bug report analyzed, but saving it failed — nothing was imported.",
        cause
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
     * Classifies an imported ZIP by its entry names (#342 spec §4.1). Reaching a
     * ZIP entry's NAME via `ZipInputStream` inflates the PRECEDING entry's body
     * (`closeEntry()`/`getNextEntry()` decompress and discard it), so this is not
     * free on a large or crafted archive. [ArtifactSniffer.classifyZip] therefore
     * (a) short-circuits on the first `dumpstate` entry — a well-formed bug report
     * is classified without draining bodies — and (b) caps total decompressed
     * bytes so a deflate bomb cannot inflate unboundedly here (security M5). The
     * analyzer then re-opens the URI to read the content.
     */
    private suspend fun sniffArtifact(uri: Uri): ArtifactType = withContext(Dispatchers.IO) {
        val stream = context.contentResolver.openInputStream(uri)
            ?: return@withContext ArtifactType.UNRECOGNIZED
        stream.use { s -> ArtifactSniffer.classifyZip(s).type }
    }

    /**
     * #342: analyze an Advanced Protection Intrusion Logging export in one pass, appending each
     * type's chunk to an import session as it fills (rules see every record; only the Timeline rows
     * are capped, spec §7). The finishing transaction first sweeps the previous imports' Timeline
     * rows (replace-on-reimport, B1), so a failed import rolls that back too.
     *
     * Failure honesty (B1, #356): the session is aborted and nothing is kept; an analysis failure
     * rethrows [IntrusionLogAnalyzer.IntrusionLogAnalysisException], any other failure
     * [IntrusionLogPersistException], so the ViewModel's error card says nothing was imported
     * instead of rendering a summary for data that is not in the database.
     */
    @Suppress("TooGenericExceptionCaught")
    suspend fun analyzeIntrusionLog(uri: Uri): IntrusionLogAnalysisResult =
        // CPU work (rules, records, session) off the caller's Main; the lock is outside any transaction (A8 D2).
        scanLock.withWriter { withContext(Dispatchers.Default) {
        initRuleEngine()
        val now = System.currentTimeMillis()
        val scan = ScanResult(
            id = now, timestamp = now, findings = emptyList(), bugReportFindings = emptyList(),
            riskySideloadCount = 0, knownMalwareCount = 0,
            // #356: see analyzeBugReport — imports are labeled, not passed off
            // as live scans of this device.
            source = TelemetrySource.INTRUSION_LOG_IMPORT,
        )
        val hooks = IntrusionLogHooks(scan, sigmaRuleEngine, sigmaCorrelationEngine, forensicTimelineEventDao,
            timelineRows)
        try {
            writer.inSession(scan, liveEvents = false, hooks) { session ->
                val analysis = intrusionLogAnalyzer.analyze(uri, IntrusionLogSessionChunks(session, hooks.interim, now))
                hooks.errors.addAll(analysis.scannerErrors)
                intrusionLogResult(analysis, requireSaved(session.finish()), hooks)
            }
        } catch (c: CancellationException) {
            throw c
        } catch (e: IntrusionLogAnalyzer.IntrusionLogAnalysisException) {
            throw e
        } catch (t: Throwable) {
            // Do NOT swallow: a swallowed failure here (the original behavior) left the
            // prior import deleted, the new one unwritten, and the UI still reporting success.
            Log.e(TAG, "Failed to persist intrusion log import", t)
            throw IntrusionLogPersistException(t)
        }
    } }

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
        // Every reason a rule produced no verdict, not just the one this filter was
        // written for. A rule the newer scan could not evaluate has not been fixed,
        // and "resolved" on a CRITICAL nobody checked is the false reassurance this
        // function's contract forbids.
        val skippedRuleIds = newer.scannerErrors
            .filter { it.exception in NotEvaluatedReason.SENTINELS }
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
         * Every `display.evidence_type` (other than `none`) a rule may declare must have a
         * provider here. From March to October 2026 androdr-001..003 declared `ioc_match`
         * with no provider registered, so the evaluator silently fell back to no evidence
         * and IOC findings never named the matched family. EvidenceProviderCoverageTest
         * fails the build on a declared type missing from this set; initRuleEngine checks
         * the provider map against it at runtime.
         */
        val REGISTERED_EVIDENCE_TYPES: Set<String> = setOf("cve_list", "ioc_match")

        internal fun buildEvidenceProviders(
            rules: List<SigmaRule>,
            iocRow: (lookupDb: String, value: String) -> Indicator?
        ): Map<String, EvidenceProvider> = mapOf(
            "cve_list" to CveEvidenceProvider(rules),
            "ioc_match" to IocMatchEvidenceProvider(iocRow),
        )

        /**
         * The stored row behind an `ioc_lookup` match, for the ioc_match provider.
         *
         * Domains: the prefetched row is read ONLY when [value] matches live (bloom or
         * bundle) right now. Prefetched rows are never evicted, so a stale one can outlive
         * its indicator; it is never evidence that a domain is an IOC. A live match with
         * no prefetched row is recorded in [IndicatorResolver.attributionMisses].
         */
        internal fun iocRow(resolver: IndicatorResolver, lookupDb: String, value: String): Indicator? =
            when (lookupDb) {
                "package_ioc_db" -> resolver.packageIndicator(value)
                "cert_hash_ioc_db" -> resolver.isKnownBadCert(value)
                "apk_hash_ioc_db" -> resolver.isKnownBadApkHash(value)
                "domain_ioc_db" -> if (resolver.isKnownBadDomainWithBundle(value) == null) {
                    null
                } else {
                    resolver.cachedDomainIndicator(value)
                        ?: null.also { resolver.attributionMisses.updateAndGet { it + value } }
                }
                else -> null
            }

        /**
         * Cap on the feed-controlled `ioc_lookup` name echoed into a
         * capability-skip message. Real names are short snake_case identifiers
         * (`trusted_installer_db` is 20 chars), so this is generous while still
         * bounding a hostile rule's contribution to one report line.
         */
        /**
         * Reduces a feed-controlled lookup name to printable ASCII, then caps its
         * length. Delegates to [reportSafe], which every path writing feed text into
         * a report now shares -- including [RuleCoverage], which writes rule titles
         * into the same section.
         */
        private fun sanitizeLookupName(name: String): String = reportSafe(name)

        /** [ScannerFailure.scanner] of a live scan whose writer session failed (nothing was kept). */
        const val SCAN_WRITER = "scanWriter"

        private fun writerFailure(t: Throwable) =
            ScannerFailure(scanner = SCAN_WRITER, exception = t.javaClass.simpleName, message = t.message)

        /** APK hash by package from stored `app_scanner` records (empty and absent hashes skipped). */
        internal fun storedHashByPackage(apps: List<DecodedRecord>): Map<String, String> = buildMap {
            apps.forEach { r ->
                val pkg = r.fields?.get("package_name") as? String
                val hash = r.fields?.get("apk_hash") as? String
                if (!pkg.isNullOrEmpty() && !hash.isNullOrEmpty()) put(pkg, hash)
            }
        }

        /** APK hash per package, for enriching finding rows that carry none. */
        internal fun hashByPackage(apps: List<AppTelemetry>): Map<String, String> =
            apps.filter { !it.apkHash.isNullOrEmpty() }.associateBy({ it.packageName }, { it.apkHash!! })

        /**
         * The triggered findings to PERSIST for one intrusion-log import (#342 B3), capped at
         * [FINDINGS_PERSIST_CAP]. Below the cap the input order is preserved (no reshuffle); above
         * it, findings are ranked highest-severity first and, for equal severity, most-recent first
         * (by the finding's own event time), so the rows most worth keeping survive the cut. Only
         * triggered findings are ever persisted. The session's streaming [FindingsTopK] keeps
         * exactly this set and order; this is its reference definition.
         */
        @VisibleForTesting
        internal fun capTriggeredFindings(findings: List<Finding>): List<Finding> {
            val triggered = findings.filter { it.triggered }
            if (triggered.size <= FINDINGS_PERSIST_CAP) return triggered
            return triggered.sortedWith(
                compareByDescending<Finding> { FindingRank.severity(it.level) }
                    .thenByDescending { FindingRank.eventTimeMs(it) }
            ).take(FINDINGS_PERSIST_CAP)
        }

        /**
         * #342 spec §7: Timeline-row caps per import (newest first); rules always see the full
         * stream. Interim until Task C3. The worst-case rows one import writes is
         * FINDINGS_PERSIST_CAP + DNS + CONNECT + SECURITY (= 21000), above
         * [ForensicTimelineEventDao.getAllForExport]'s `LIMIT 10000` (follow-up #353).
         */
        const val DNS_PERSIST_CAP = 10_000
        const val CONNECT_PERSIST_CAP = 5_000

        /**
         * Cap on triggered findings PERSISTED per import (#342 B3). One Finding is
         * emitted per (record × matching rule) over the uncapped parsed stream, so
         * a single beaconing domain resolved thousands of times can produce
         * thousands of findings; persisting them all bloats the ScanResult JSON
         * column past Room's ~2 MB CursorWindow and throws
         * SQLiteBlobTooBigException on EVERY subsequent history read. 1000 is far
         * above any real intrusion log's distinct-finding count while bounding the
         * pathological/hostile case. Detection is unaffected — rules already ran
         * over everything; this bounds only what is stored.
         */
        const val FINDINGS_PERSIST_CAP = 1_000

        /**
         * Cap on `security_event` rows PERSISTED per import (#342 B4, security L1).
         * Security events are the rarest, highest-signal records, so this was
         * originally uncapped — but that let an attacker-crafted export of millions
         * of `security_event` lines persist millions of rows surviving the 30-day
         * retention (storage DoS). 5000 (matching [CONNECT_PERSIST_CAP]) is far
         * above any legitimate export's security-event volume while bounding abuse.
         */
        const val SECURITY_PERSIST_CAP = 5_000

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
