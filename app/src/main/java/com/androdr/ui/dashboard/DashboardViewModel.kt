package com.androdr.ui.dashboard

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.ScanRepository
import com.androdr.data.repo.ScanRepository.Companion.preferRuntimeScan
import com.androdr.ioc.IocDatabase
import com.androdr.ioc.IndicatorUpdater
import com.androdr.scanner.ScanOrchestrator
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
    private val indicatorUpdater: IndicatorUpdater,
    @ApplicationContext private val context: Context
) : ViewModel() {

    // Prefer the latest runtime scan (has device posture flags) over bugreport analysis
    val latestScan: StateFlow<ScanResult?> = repository.allScans
        .map { scans -> scans.preferRuntimeScan() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

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
                    System.currentTimeMillis() - (_iocLastUpdated.value ?: 0L) > 24 * 60 * 60 * 1000L
                val hasOnlyBundled = _iocEntryCount.value <= bundledCount
                if (isStale || hasOnlyBundled) {
                    doUpdate()
                }
                orchestrator.runFullScan()
            } finally {
                _isScanning.value = false
            }
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun doUpdate() {
        try {
            indicatorUpdater.update()
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
        _iocLastUpdated.value = indicatorDao.lastFetchTime("stalkerware_indicators")
    }
}
