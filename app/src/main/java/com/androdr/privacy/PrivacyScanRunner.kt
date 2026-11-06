package com.androdr.privacy

import android.util.Log
import androidx.annotation.VisibleForTesting
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.DomainLookupCount
import com.androdr.data.db.PrivacyDao
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyPackageSet
import com.androdr.data.model.PrivacyScan
import com.androdr.di.ApplicationScope
import com.androdr.ioc.TrackerRegistry
import com.androdr.privacy.DexPackageReader.ReadBudget
import com.androdr.privacy.NetworkEvidenceCorrelator.DnsSource
import com.androdr.privacy.NetworkEvidenceCorrelator.Key
import com.androdr.privacy.NetworkEvidenceCorrelator.NetworkEvidence
import com.androdr.privacy.model.Tracker
import com.androdr.privacy.model.TrackerSet
import com.androdr.util.reportSafe
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import javax.inject.Inject
import javax.inject.Singleton

sealed class PrivacyScanProgress {
    object Idle : PrivacyScanProgress()
    data class Running(val done: Int, val total: Int) : PrivacyScanProgress()
    data class Finished(val scanId: Long) : PrivacyScanProgress()
    data class Failed(val message: String) : PrivacyScanProgress()
}

/**
 * Runs the privacy scan: inspects every installed app's code for tracker SDKs, correlates 30 days of attributed DNS
 * lookups with the tracker registry, and stores the results in the privacy tables. It has its own lock and never
 * waits on, or writes to, the security scan. A hostile app costs only itself: an app whose APK exhausts memory or
 * time is recorded as could-not-inspect, and a DNS-log flood or a failing DNS read costs only network evidence.
 */
// Throwable is caught on purpose: OutOfMemoryError and StackOverflowError from a crafted APK must cost one app.
@Suppress("TooGenericExceptionCaught")
@Singleton
class PrivacyScanRunner @Inject constructor(
    private val inspector: AppInspector,
    private val registry: TrackerRegistry,
    private val dao: PrivacyDao,
    private val dnsEvents: DnsEventDao,
    private val usage: UsageIntervalReader,
    @ApplicationScope private val scope: CoroutineScope,
) {
    // Test seams: Hilt cannot inject function types and the project has no clock abstraction. Production never
    // assigns them.
    @VisibleForTesting internal var clock: () -> Long = System::currentTimeMillis
    @VisibleForTesting internal var nanoTime: () -> Long = System::nanoTime

    private val mutex = Mutex()
    private val state = MutableStateFlow<PrivacyScanProgress>(PrivacyScanProgress.Idle)
    val progress: StateFlow<PrivacyScanProgress> = state.asStateFlow()

    /** = registry.available; the bundled load is triggered on IO here. The UI reads this, never the registry. */
    val registryAvailable: StateFlow<Boolean> = registry.available

    init {
        // available stays false until the first current() call, which parses the bundled file (slow).
        scope.launch(Dispatchers.IO) { registry.current() }
    }

    /** Starts a scan on the application scope (Dispatchers.IO) unless one is running; false when one already is. */
    fun start(): Boolean {
        if (!mutex.tryLock()) return false
        state.value = PrivacyScanProgress.Running(0, 0)
        val job = scope.launch(Dispatchers.IO) {
            try {
                runScan()
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                Log.w(TAG, "Privacy scan failed: ${t.javaClass.simpleName}")
                state.value = PrivacyScanProgress.Failed(reportSafe(t.javaClass.simpleName))
            }
        }
        // Runs even when the job is cancelled before it starts, so the lock is always released.
        job.invokeOnCompletion {
            if (state.value is PrivacyScanProgress.Running) state.value = PrivacyScanProgress.Failed(CANCELLED)
            mutex.unlock()
        }
        return true
    }

    /** Deletes every privacy row; false (nothing deleted) while a scan runs. */
    suspend fun deleteAll(): Boolean {
        if (!mutex.tryLock()) return false
        try {
            dao.deleteAll()
            state.value = PrivacyScanProgress.Idle
        } finally {
            mutex.unlock()
        }
        return true
    }

    private suspend fun runScan() {
        // Read once: a registry refresh during the scan does not change the set this scan uses.
        val set = registry.current()
        if (set == null) {
            state.value = PrivacyScanProgress.Failed(REGISTRY_UNAVAILABLE)
            return
        }
        val previous = dao.latestCompletedOnce()
        val apps = inspector.installedApps()
        val startedAt = clock()
        val windowStart = startedAt - DNS_WINDOW_MS
        val scanId = dao.insertScan(
            PrivacyScan(
                startedAt = startedAt, finishedAt = null, appsTotal = apps.size, appsInspected = 0,
                appsPartial = 0, appsFailed = 0, registrySize = set.size, registrySha256 = set.sourceSha256,
                dnsWindowStart = windowStart, dnsCoverageDays = 0, usageCoverageFrom = null,
                networkStatus = NetworkStatus.PENDING.name,
            )
        )
        state.value = PrivacyScanProgress.Running(0, apps.size)
        val outcomes = HashMap<String, InspectOutcome>()
        val inCode = HashMap<String, Set<Tracker>>()
        for ((index, app) in apps.withIndex()) {
            val inspection = inspect(app)
            dao.upsertResults(listOf(resultRow(scanId, inspection)))
            outcomes[app.packageName] = inspection.outcome
            inCode[app.packageName] = set.matchPackages(inspection.packages)
            state.value = PrivacyScanProgress.Running(index + 1, apps.size)
        }
        val usageIntervals = readUsage(windowStart, startedAt)
        val (correlated, network) = correlate(set, outcomes.keys, usageIntervals, windowStart)
        val coverage = coverageDays(windowStart)
        // Without coverage the network evidence cannot be judged complete.
        val status = if (coverage == null) NetworkStatus.FAILED else correlated
        val isNew = PrivacyEvidenceRows.newSince(
            previous?.let { dao.resultsOnce(it.id) },
            previous?.let { dao.evidenceOnce(it.id) },
        )
        dao.upsertEvidence(PrivacyEvidenceRows.build(scanId, set, inCode, network, isNew))
        dao.finishScan(
            scanId, clock(), outcomes.values.count { it == InspectOutcome.INSPECTED },
            outcomes.values.count { it == InspectOutcome.PARTIAL },
            outcomes.values.count { it == InspectOutcome.COULD_NOT_INSPECT },
            coverage ?: 0, usageIntervals?.coverageFrom, status.name,
        )
        dao.deleteScansBefore(scanId)
        dao.pruneCacheTo(scanId)
        state.value = PrivacyScanProgress.Finished(scanId)
    }

    private fun resultRow(scanId: Long, i: AppInspection) = PrivacyAppResult(
        scanId = scanId, packageName = i.app.packageName, versionCode = i.app.versionCode, appLabel = i.app.appLabel,
        isSystemApp = i.app.isSystemApp, outcome = i.outcome.name, reason = i.reason,
    )

    /** One app, isolated: whatever its APK does to the reader (OOM included) costs only this app. */
    private suspend fun inspect(app: InstalledApp): AppInspection = try {
        cachedPackages(app)?.let { AppInspection(app, it, InspectOutcome.INSPECTED, null) } ?: inspectAndCache(app)
    } catch (c: CancellationException) {
        throw c
    } catch (t: Throwable) {
        Log.w(TAG, "Could not inspect ${app.packageName}: ${t.javaClass.simpleName}")
        val reason = "resource limit: ${reportSafe(t.javaClass.simpleName)}"
        AppInspection(app, emptySet(), InspectOutcome.COULD_NOT_INSPECT, reason)
    }

    /** The cached package set when version, update time and reader version all match; an unreadable row is deleted. */
    private suspend fun cachedPackages(app: InstalledApp): Set<String>? {
        val row = try {
            dao.packageSet(app.packageName)
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            Log.w(TAG, "Unreadable package-set cache for ${app.packageName}: ${t.javaClass.simpleName}")
            dao.deletePackageSet(app.packageName)
            null
        }
        val fresh = row?.takeIf {
            it.versionCode == app.versionCode && it.lastUpdateTime == app.lastUpdateTime &&
                it.readerVersion == READER_VERSION
        }
        return fresh?.packagesText?.split('\n')?.filterTo(LinkedHashSet()) { it.isNotEmpty() }
    }

    private suspend fun inspectAndCache(app: InstalledApp): AppInspection {
        val budget = ReadBudget(deadlineNanos = nanoTime() + PER_APP_TIMEOUT_MS * NANOS_PER_MS, nanoTime = nanoTime)
        val inspection = inspector.inspect(app, budget)
        if (inspection.outcome == InspectOutcome.INSPECTED) cache(app, inspection.packages)
        return inspection
    }

    /** Only complete package sets small enough to read back through a cursor window are cached; best effort. */
    private suspend fun cache(app: InstalledApp, packages: Set<String>) {
        val text = packages.joinToString("\n")
        if (text.toByteArray(Charsets.UTF_8).size > MAX_PACKAGES_TEXT_BYTES) return
        try {
            dao.upsertPackageSet(
                PrivacyPackageSet(app.packageName, app.versionCode, app.lastUpdateTime, READER_VERSION, text)
            )
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            Log.w(TAG, "Package-set cache write failed for ${app.packageName}: ${t.javaClass.simpleName}")
        }
    }

    /** null = no usage data (no access, or the read failed): background counts are then unknown. */
    private fun readUsage(since: Long, until: Long): UsageIntervals? = try {
        usage.read(since, until)
    } catch (t: Throwable) {
        Log.w(TAG, "Usage intervals unavailable: ${t.javaClass.simpleName}")
        null
    }

    /** Network, isolated: a failure here costs only the network evidence; the code results still finish. */
    private suspend fun correlate(
        set: TrackerSet,
        installed: Set<String>,
        usage: UsageIntervals?,
        since: Long,
    ): Pair<NetworkStatus, Map<Key, NetworkEvidence>> = try {
        val deadline = nanoTime() + NETWORK_TIMEOUT_MS * NANOS_PER_MS
        val c = NetworkEvidenceCorrelator.correlate(dnsSource(since), set, installed, usage) { nanoTime() > deadline }
        (if (c.truncated) NetworkStatus.TRUNCATED else NetworkStatus.COMPLETE) to c.evidence
    } catch (c: CancellationException) {
        throw c
    } catch (t: Throwable) {
        Log.w(TAG, "Network correlation failed: ${t.javaClass.simpleName}")
        NetworkStatus.FAILED to emptyMap()
    }

    /** null = the DNS log could not be read. */
    private suspend fun coverageDays(since: Long): Int? = try {
        dnsEvents.coverageDaysSince(since)
    } catch (c: CancellationException) {
        throw c
    } catch (t: Throwable) {
        Log.w(TAG, "DNS coverage unavailable: ${t.javaClass.simpleName}")
        null
    }

    private fun dnsSource(since: Long) = object : DnsSource {
        override suspend fun domainsAfter(app: String, afterDomain: String, limit: Int): List<String> =
            dnsEvents.domainsAfter(since, app, afterDomain, limit)

        override suspend fun count(app: String, rawDomain: String): DomainLookupCount =
            dnsEvents.lookupCount(since, app, rawDomain)

        override suspend fun times(app: String, rawDomain: String, limit: Int): List<Long> =
            dnsEvents.lookupTimes(since, app, rawDomain, limit)
    }

    companion object {
        private const val TAG = "PrivacyScanRunner"
        private const val NANOS_PER_MS = 1_000_000L
        const val DNS_WINDOW_MS = 30L * 24 * 3600 * 1000
        const val PER_APP_TIMEOUT_MS = 30_000L
        const val NETWORK_TIMEOUT_MS = 60_000L
        const val READER_VERSION = 1

        /** UTF-8 bytes, below the 2 MB CursorWindow. */
        const val MAX_PACKAGES_TEXT_BYTES = 1_000_000
        const val REGISTRY_UNAVAILABLE = "tracker registry unavailable"

        /** The run ended by cancellation (the process scope, say) without finishing or failing. */
        const val CANCELLED = "scan cancelled"
    }
}
