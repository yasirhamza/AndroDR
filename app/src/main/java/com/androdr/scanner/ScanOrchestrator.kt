package com.androdr.scanner

import android.net.Uri
import android.util.Log
import com.androdr.data.model.AppRisk
import com.androdr.data.model.DeviceFlag
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.ScanRepository
import com.androdr.ioc.CertHashIocResolver
import com.androdr.ioc.DomainIocResolver
import com.androdr.ioc.IocResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import com.androdr.sigma.FindingMapper
import com.androdr.sigma.SigmaRuleFeed
import com.androdr.sigma.SigmaRuleEngine
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Orchestrates all scanning operations.  Runs [AppScanner] and [DeviceAuditor] in parallel,
 * assembles a [ScanResult], persists it, and exposes helpers for bug-report analysis and
 * result diffing.
 */
@Singleton
class ScanOrchestrator @Inject constructor(
    private val appScanner: AppScanner,
    private val deviceAuditor: DeviceAuditor,
    private val processScanner: ProcessScanner,
    private val fileArtifactScanner: FileArtifactScanner,
    private val bugReportAnalyzer: BugReportAnalyzer,
    private val scanRepository: ScanRepository,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val iocResolver: IocResolver,
    private val certHashIocResolver: CertHashIocResolver,
    private val domainIocResolver: DomainIocResolver,
    private val sigmaRuleFeed: SigmaRuleFeed
) {

    private var ruleEngineInitialized = false

    private suspend fun initRuleEngine() {
        if (ruleEngineInitialized) return
        sigmaRuleEngine.setIocLookups(mapOf(
            "package_ioc_db" to { v -> iocResolver.isKnownBadPackage(v.toString()) != null },
            "cert_hash_ioc_db" to { v -> certHashIocResolver.isKnownBadCert(v.toString()) != null },
            "domain_ioc_db" to { v -> domainIocResolver.isKnownBadDomain(v.toString()) != null }
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

        val appTelemetry = appTelemetryDeferred.await()
        val deviceTelemetry = deviceTelemetryDeferred.await()
        val processTelemetry = processTelemetryDeferred.await()
        val fileTelemetry = fileTelemetryDeferred.await()

        // Phase 2: SIGMA rule evaluation — all detection via rules
        val appFindings = sigmaRuleEngine.evaluateApps(appTelemetry)
        val appRisks = FindingMapper.toAppRisks(appTelemetry, appFindings)

        val deviceFindings = sigmaRuleEngine.evaluateDevice(deviceTelemetry)
        val deviceFlags = FindingMapper.toDeviceFlags(deviceTelemetry, deviceFindings)

        val processFindings = sigmaRuleEngine.evaluateProcesses(processTelemetry)
        val fileFindings = sigmaRuleEngine.evaluateFiles(fileTelemetry)

        val totalFindings = appFindings.size + deviceFindings.size +
            processFindings.size + fileFindings.size
        Log.i(TAG, "Scan complete — SIGMA: $totalFindings findings from " +
            "${sigmaRuleEngine.ruleCount()} rules → ${appRisks.size} app risks, " +
            "${deviceFlags.count { it.isTriggered }} device flags triggered, " +
            "${processFindings.size} process findings, ${fileFindings.size} file findings")

        val now = System.currentTimeMillis()
        val result = ScanResult(
            id                 = now,
            timestamp          = now,
            appRisks           = appRisks,
            deviceFlags        = deviceFlags,
            bugReportFindings  = emptyList(),
            riskySideloadCount = appRisks.count { it.isSideloaded },
            knownMalwareCount  = appRisks.count { it.isKnownMalware }
        )

        runCatching { scanRepository.saveScan(result) }
        result
    }

    /**
     * Delegates to [BugReportAnalyzer.analyze].
     *
     * @param uri Content URI pointing to the bugreport .zip file.
     * @return List of [BugReportFinding] items (may be empty on a clean report).
     */
    suspend fun analyzeBugReport(uri: Uri): List<BugReportFinding> =
        bugReportAnalyzer.analyze(uri)

    /**
     * Computes a diff between two [ScanResult] snapshots.
     *
     * @param newer The more recent scan result.
     * @param older The earlier scan result used as the baseline.
     * @return A [ScanDiff] describing what changed between the two scans.
     */
    fun computeDiff(newer: ScanResult, older: ScanResult): ScanDiff {
        val olderPackageNames = older.appRisks.map { it.packageName }.toSet()
        val newerPackageNames = newer.appRisks.map { it.packageName }.toSet()

        val newRisks      = newer.appRisks.filter { it.packageName !in olderPackageNames }
        val resolvedRisks = older.appRisks.filter { it.packageName !in newerPackageNames }

        val olderFlagIds = older.deviceFlags
            .filter { it.isTriggered }
            .map { it.id }
            .toSet()
        val newerFlagIds = newer.deviceFlags
            .filter { it.isTriggered }
            .map { it.id }
            .toSet()

        val newFlags      = newer.deviceFlags.filter { it.isTriggered && it.id !in olderFlagIds }
        val resolvedFlags = older.deviceFlags.filter { it.isTriggered && it.id !in newerFlagIds }

        return ScanDiff(
            newRisks      = newRisks,
            resolvedRisks = resolvedRisks,
            newFlags      = newFlags,
            resolvedFlags = resolvedFlags
        )
    }

    /**
     * Describes the delta between two consecutive scans.
     *
     * @property newRisks      Risky apps present in [newer] but not in [older].
     * @property resolvedRisks Risky apps that were in [older] but are no longer in [newer].
     * @property newFlags      Device-level flags that became triggered in [newer].
     * @property resolvedFlags Device-level flags that were triggered in [older] but not in [newer].
     */
    data class ScanDiff(
        val newRisks:      List<AppRisk>,
        val resolvedRisks: List<AppRisk>,
        val newFlags:      List<DeviceFlag>,
        val resolvedFlags: List<DeviceFlag>
    )

    companion object {
        private const val TAG = "ScanOrchestrator"
    }
}
