package com.androdr.ui.dashboard

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetryState
import com.androdr.data.repo.ScanRepository
import com.androdr.data.store.DnsDropLog
import com.androdr.data.store.DnsDropState
import com.androdr.data.store.StorageHealthFlag
import com.androdr.data.repo.ScanRepository.Companion.preferRuntimeScan
import com.androdr.ioc.IntelRefresher
import com.androdr.ioc.IocDatabase
import com.androdr.scanner.ScanOrchestrator
import com.androdr.scanner.ScanProgress
import com.androdr.ui.permissions.UsageStatsPermission
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val orchestrator: ScanOrchestrator,
    private val repository: ScanRepository,
    private val indicatorDao: IndicatorDao,
    private val iocDatabase: IocDatabase,
    private val intelRefresher: IntelRefresher,
    private val storageHealth: StorageHealthFlag,
    private val dnsDropLog: DnsDropLog,
    @ApplicationContext private val context: Context
) : ViewModel() {

    // Prefer the latest runtime scan (has device posture flags) over bugreport analysis
    /**
     * The scan that just ran but is not in history (its write failed; only the in-memory result exists).
     * It stands in for the latest scan so an older clean scan never reads as the answer for it.
     */
    private val _unsavedScan = MutableStateFlow<ScanResult?>(null)

    val latestScan: StateFlow<ScanResult?> = combine(repository.allScans, _unsavedScan) { scans, unsaved ->
        resolveLatest(scans, unsaved)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    /** True while [latestScan] is a result that could not be saved at all. */
    val latestUnsaved: StateFlow<Boolean> = _unsavedScan.map { it != null }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    /** The persistent "a scan's findings could not be saved" flag (cleared by the next stored scan). */
    val storageHealthFailed: StateFlow<Boolean> = storageHealth.isSetFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    /** DNS events the VPN log had to discard; shown until the user dismisses it. */
    val dnsDrops: StateFlow<DnsDropState> = dnsDropLog.state
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DnsDropState(0L, 0L))

    fun dismissDnsDrops() {
        viewModelScope.launch { dnsDropLog.clear() }
    }

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    /**
     * True while a scan is blocked on the pre-scan threat-intel refresh. Lets
     * the Dashboard show "Updating threat intel…" instead of a generic
     * "Scanning…" with a non-advancing bar during the (potentially ~30s)
     * network refresh, so the scan doesn't look hung.
     */
    private val _isUpdatingIntel = MutableStateFlow(false)
    val isUpdatingIntel: StateFlow<Boolean> = _isUpdatingIntel.asStateFlow()

    /**
     * Live scan progress published by the orchestrator. The Dashboard UI
     * observes this to render a progress bar + stage text instead of the
     * bare spinning button the app used to show.
     */
    val scanProgress: StateFlow<ScanProgress> = orchestrator.scanProgress

    /**
     * Whether the app currently has the PACKAGE_USAGE_STATS permission, which
     * the forensic timeline (via [com.androdr.scanner.UsageStatsScanner])
     * needs to populate "app opened / closed" history. Checked imperatively
     * via [UsageStatsPermission.isGranted] because the OS doesn't expose
     * this as an observable flow — instead the UI calls
     * [refreshUsageStatsPermission] from a lifecycle ON_RESUME hook so the
     * banner state updates the moment the user grants access and returns
     * from Settings.
     */
    private val _hasUsageStatsPermission = MutableStateFlow(
        UsageStatsPermission.isGranted(context)
    )
    val hasUsageStatsPermission: StateFlow<Boolean> = _hasUsageStatsPermission.asStateFlow()

    /** Re-checks Usage Access permission. Called from the Dashboard on ON_RESUME. */
    fun refreshUsageStatsPermission() {
        _hasUsageStatsPermission.value = UsageStatsPermission.isGranted(context)
    }

    /** Opens the system Usage Access settings screen. */
    fun openUsageStatsSettings() {
        UsageStatsPermission.openSettings(context)
    }

    val scanDiff: StateFlow<ScanOrchestrator.ScanDiff?> = repository.allScans
        .map { scans ->
            if (scans.size >= 2) orchestrator.computeDiff(scans[0], scans[1]) else null
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    val matchedDnsCount: StateFlow<Int> = repository.matchedDnsEvents
        .map { it.size }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)

    private val bundledCount = iocDatabase.getAllBadPackages().size

    private val _iocEntryCount = MutableStateFlow(bundledCount)

    private val _iocLastUpdated = MutableStateFlow<Long?>(null)

    private val _iocErrorEvent = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val iocErrorEvent: SharedFlow<String> = _iocErrorEvent.asSharedFlow()

    init {
        viewModelScope.launch {
            refreshIocState()
        }
    }

    fun runScan() {
        viewModelScope.launch {
            _isScanning.value = true
            try {
                val isStale = _iocLastUpdated.value == null ||
                    System.currentTimeMillis() - (_iocLastUpdated.value ?: 0L) > PRE_SCAN_REFRESH_THROTTLE_MS
                val hasOnlyBundled = _iocEntryCount.value <= bundledCount
                if (isStale || hasOnlyBundled) {
                    _isUpdatingIntel.value = true
                    try {
                        doUpdate()
                    } finally {
                        _isUpdatingIntel.value = false
                    }
                }
                val result = orchestrator.runFullScan()
                // A history read that fails leaves the state as it was: neither "saved" nor "unsaved" is known.
                outcomeOf(result, readPersisted { repository.allScans.first() })?.let { outcome ->
                    _unsavedScan.value = outcome.unsaved
                    if (outcome.clearHealthFlag) storageHealth.clear()
                }
            } finally {
                _isScanning.value = false
            }
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun doUpdate() {
        try {
            intelRefresher.refreshAll(skipIfRefreshedWithinMs = PRE_SCAN_REFRESH_THROTTLE_MS)
            refreshIocState()
            // Only warn if DB is still empty after update attempt (not just zero new entries)
            if (_iocEntryCount.value <= bundledCount) {
                _iocErrorEvent.tryEmit("Failed to update threat database. Check your connection.")
            }
        } catch (e: Exception) {
            _iocErrorEvent.tryEmit("Threat database update failed: ${e.message}")
        }
    }

    private suspend fun refreshIocState() {
        _iocEntryCount.value = indicatorDao.count() + bundledCount
        _iocLastUpdated.value = indicatorDao.lastFetchTimeGlobal()
    }

    companion object {
        /**
         * [NOT_SAVED]: the latest result exists only in memory, or the "findings could not be saved"
         * flag is set. [PARTLY_STORED]: the latest scan is saved but its [TelemetryState] is FAILED
         * (some records were not stored; findings are complete). Nothing while a scan runs.
         */
        fun storageBanner(scan: ScanResult?, isScanning: Boolean, unsaved: Boolean, healthFailed: Boolean) = when {
            isScanning -> StorageBanner.NONE
            unsaved -> StorageBanner.NOT_SAVED
        healthFailed -> StorageBanner.EARLIER_SCAN_SHOWN
            scan?.telemetryState == TelemetryState.FAILED -> StorageBanner.PARTLY_STORED
            else -> StorageBanner.NONE
        }

        /**
         * The "Correlation incomplete" warning (spec §5.2): one line per chain rule the correlation
         * budget cut off or never started on [scan], naming the rule and the packages. Separate from
         * the scanner-failure banner — nothing failed; an app flooding events can cause it. Empty
         * while a scan runs.
         */
        fun correlationIncomplete(scan: ScanResult?, isScanning: Boolean): List<String> =
            if (isScanning || scan == null) {
                emptyList()
            } else {
                scan.scannerErrors
                    .filter { it.exception == NotEvaluatedReason.CORRELATION_INCOMPLETE.sentinel }
                    .mapNotNull { it.message }
            }

        /** The unsaved in-memory result wins over history: an older clean scan must not answer for it. */
        fun resolveLatest(persisted: List<ScanResult>, unsaved: ScanResult?): ScanResult? =
            unsaved ?: persisted.preferRuntimeScan()

        /** What a finished run means for the Dashboard state. */
        class ScanOutcome(val unsaved: ScanResult?, val clearHealthFlag: Boolean)

        /** Null when history could not be read ([persisted] null): nothing can be concluded. */
        fun outcomeOf(result: ScanResult, persisted: List<ScanResult>?): ScanOutcome? =
            persisted?.let { ScanOutcome(unsavedOrNull(result, it), shouldClearHealthFlag(result, it)) }

        /** Reads history; a failed read (the failure mode this feature exists for) gives null. */
        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        suspend fun readPersisted(read: suspend () -> List<ScanResult>): List<ScanResult>? = try {
            read()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            null
        }

        /** [result] when no saved scan has its id (the write failed), else null. */
        fun unsavedOrNull(result: ScanResult, persisted: List<ScanResult>): ScanResult? =
            result.takeIf { r -> persisted.none { it.id == r.id } }

        /** A scan that was saved with all its records proves storage works again. */
        fun shouldClearHealthFlag(result: ScanResult, persisted: List<ScanResult>): Boolean =
            unsavedOrNull(result, persisted) == null && result.telemetryState != TelemetryState.FAILED

        /**
         * A manual scan refreshes threat intel first, but only if the last
         * refresh is older than this. Prevents back-to-back full syncs
         * (~6–8 MB each) on rapid re-scans while still giving a deliberate
         * scan fresh intel. The background worker refreshes every 12h anyway.
         */
        private const val PRE_SCAN_REFRESH_THROTTLE_MS = 60L * 60 * 1000 // 1 hour
    }
}

/** Which storage warning the Dashboard shows, if any. */
enum class StorageBanner {
    NONE,
    PARTLY_STORED,

    /** The scan on screen exists only in memory. */
    NOT_SAVED,

    /** A recent scan or import could not be saved, but the scan on screen is an earlier, saved one. */
    EARLIER_SCAN_SHOWN,
}
