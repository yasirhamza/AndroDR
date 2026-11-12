package com.androdr.privacy

import android.util.Log
import androidx.annotation.VisibleForTesting
import androidx.room.withTransaction
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.DomainLookupCount
import com.androdr.data.db.PrivacyDao
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyCodeDetail
import com.androdr.data.model.PrivacyPackageSet
import com.androdr.data.model.PrivacyScan
import com.androdr.di.ApplicationScope
import com.androdr.ioc.TrackerRegistry
import com.androdr.privacy.DexPackageReader.ReadBudget
import com.androdr.privacy.NetworkEvidenceCorrelator.DnsSource
import com.androdr.privacy.NetworkEvidenceCorrelator.DomainEvidence
import com.androdr.privacy.NetworkEvidenceCorrelator.Key
import com.androdr.privacy.NetworkEvidenceCorrelator.NetworkEvidence
import com.androdr.privacy.model.RegistryState
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
    private val db: AppDatabase,
    private val timeline: PrivacyTimelineWriter,
) {
    // Test seams: Hilt cannot inject function types and the project has no clock abstraction. Production never
    // assigns them.
    @VisibleForTesting internal var clock: () -> Long = System::currentTimeMillis
    @VisibleForTesting internal var nanoTime: () -> Long = System::nanoTime

    private val mutex = Mutex()
    private val state = MutableStateFlow<PrivacyScanProgress>(PrivacyScanProgress.Idle)
    val progress: StateFlow<PrivacyScanProgress> = state.asStateFlow()

    /** = registry.state; the bundled load is triggered on IO here. The UI reads this, never the registry. */
    val registryState: StateFlow<RegistryState> = registry.state

    init {
        // The state stays LOADING until the first current() call, which parses the bundled file (slow).
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
            // The Timeline entries go with the results they describe (spec 2026-11-10 §5.4).
            db.withTransaction {
                dao.deleteAll()
                timeline.clear()
            }
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
                networkStatus = NetworkStatus.PENDING.name, hasDetails = true,
            )
        )
        state.value = PrivacyScanProgress.Running(0, apps.size)
        val outcomes = HashMap<String, InspectOutcome>()
        val inCode = HashMap<String, Set<Tracker>>()
        for ((index, app) in apps.withIndex()) {
            val inspected = inspect(app, set, scanId)
            dao.upsertResults(listOf(resultRow(scanId, inspected.inspection)))
            dao.upsertCodeDetail(inspected.codeDetail)
            outcomes[app.packageName] = inspected.inspection.outcome
            inCode[app.packageName] = inspected.trackers
            state.value = PrivacyScanProgress.Running(index + 1, apps.size)
        }
        val usageIntervals = readUsage(windowStart, startedAt)
        val network = network(set, outcomes.keys, usageIntervals, windowStart)
        val isNew = PrivacyEvidenceRows.newSince(
            previous?.let { dao.resultsOnce(it.id) },
            previous?.let { dao.evidenceOnce(it.id) },
            previousNetworkComplete = previous?.networkStatus == NetworkStatus.COMPLETE.name,
        )
        dao.upsertEvidence(PrivacyEvidenceRows.build(scanId, set, inCode, network.evidence, isNew))
        dao.upsertDomainDetail(PrivacyDetailRows.domains(scanId, network.domains))
        val finishedAt = clock()
        val counts = PrivacyTimelineRows.ScanCounts(
            inspected = outcomes.values.count { it == InspectOutcome.INSPECTED },
            partial = outcomes.values.count { it == InspectOutcome.PARTIAL },
            failed = outcomes.values.count { it == InspectOutcome.COULD_NOT_INSPECT },
        )
        val entries = PrivacyTimelineRows.build(
            finishedAt, counts, dao.resultsOnce(scanId), dao.evidenceOnce(scanId), network.status,
            network.coverageDays,
        )
        // One transaction (spec 2026-11-10 §5.4): the scan completes, the previous results and their Timeline
        // entries go, and the new entries arrive together; a failure leaves the previous scan as it was.
        db.withTransaction {
            dao.finishScan(
                scanId, finishedAt, counts.inspected, counts.partial, counts.failed,
                network.coverageDays, usageIntervals?.coverageFrom, network.status.name,
            )
            dao.deleteScansBefore(scanId)
            dao.pruneCacheTo(scanId)
            timeline.replace(entries)
        }
        state.value = PrivacyScanProgress.Finished(scanId)
    }

    private fun resultRow(scanId: Long, i: AppInspection) = PrivacyAppResult(
        scanId = scanId, packageName = i.app.packageName, versionCode = i.app.versionCode, appLabel = i.app.appLabel,
        isSystemApp = i.app.isSystemApp, outcome = i.outcome.name, reason = i.reason,
    )

    /** One app's inspection, the trackers found in its code, and the detail rows that explain them. */
    private class Inspected(
        val inspection: AppInspection,
        val trackers: Set<Tracker>,
        val codeDetail: List<PrivacyCodeDetail>,
    )

    /**
     * One app, isolated: whatever its APK does to the reader or its package set does to the matcher (OOM included)
     * costs only this app. A package set is cached only once it has been matched. The trackers and their detail
     * rows come from one matching call, so the detail always explains exactly the trackers recorded.
     */
    private suspend fun inspect(app: InstalledApp, set: TrackerSet, scanId: Long): Inspected = try {
        val cached = cachedPackages(app)
        val inspection = if (cached != null) {
            AppInspection(app, cached, InspectOutcome.INSPECTED, null)
        } else {
            val deadline = nanoTime() + PER_APP_TIMEOUT_MS * NANOS_PER_MS
            inspector.inspect(app, ReadBudget(deadlineNanos = deadline, nanoTime = nanoTime))
        }
        val matches = set.matchPackagesDetailed(inspection.packages)
        val codeDetail = PrivacyDetailRows.code(scanId, app.packageName, matches)
        if (cached == null && inspection.outcome == InspectOutcome.INSPECTED) cache(app, inspection.packages)
        Inspected(inspection, matches.mapTo(LinkedHashSet()) { it.tracker }, codeDetail)
    } catch (c: CancellationException) {
        throw c
    } catch (t: Throwable) {
        Log.w(TAG, "Could not inspect ${app.packageName}: ${t.javaClass.simpleName}")
        Inspected(
            AppInspection(app, emptySet(), InspectOutcome.COULD_NOT_INSPECT, failureReason(t)), emptySet(), emptyList(),
        )
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

    private class NetworkResult(
        val status: NetworkStatus,
        val evidence: Map<Key, NetworkEvidence>,
        val coverageDays: Int,
        val domains: List<DomainEvidence>,
    )

    /**
     * Network, isolated: any failure here (correlation or the coverage read) gives FAILED with no network evidence
     * and no coverage; the code results still finish. The deadline is checked again after the coverage read.
     */
    private suspend fun network(
        set: TrackerSet,
        installed: Set<String>,
        usage: UsageIntervals?,
        since: Long,
    ): NetworkResult = try {
        val deadline = nanoTime() + NETWORK_TIMEOUT_MS * NANOS_PER_MS
        val expired = { nanoTime() > deadline }
        val c = NetworkEvidenceCorrelator.correlate(dnsSource(since), set, installed, usage, expired)
        val coverageDays = dnsEvents.coverageDaysSince(since)
        val truncated = c.truncated || expired()
        NetworkResult(
            if (truncated) NetworkStatus.TRUNCATED else NetworkStatus.COMPLETE, c.evidence, coverageDays, c.domains,
        )
    } catch (c: CancellationException) {
        throw c
    } catch (t: Throwable) {
        Log.w(TAG, "Network step failed: ${t.javaClass.simpleName}")
        NetworkResult(NetworkStatus.FAILED, emptyMap(), 0, emptyList())
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
        /** 2: an app with code stored outside its APKs is no longer INSPECTED, so v1 cache rows are not reused. */
        const val READER_VERSION = 2

        /** UTF-8 bytes, below the 2 MB CursorWindow. */
        const val MAX_PACKAGES_TEXT_BYTES = 1_000_000
        const val REGISTRY_UNAVAILABLE = "tracker registry unavailable"

        /** The run ended by cancellation (the process scope, say) without finishing or failing. */
        const val CANCELLED = "scan cancelled"

        /**
         * The could-not-inspect reason for a throwable caught while inspecting one app: only the memory and stack
         * errors are a "resource limit"; anything else (an unreadable file, a parser bug) "could not read".
         */
        private fun failureReason(t: Throwable): String {
            val name = reportSafe(t.javaClass.simpleName)
            val limit = t is OutOfMemoryError || t is StackOverflowError
            return if (limit) "resource limit: $name" else "could not read: $name"
        }
    }
}
