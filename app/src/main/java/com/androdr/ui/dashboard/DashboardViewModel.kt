package com.androdr.ui.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.db.IocEntryDao
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.ScanRepository
import com.androdr.ioc.IocDatabase
import com.androdr.ioc.RemoteIocUpdater
import com.androdr.scanner.ScanOrchestrator
import dagger.hilt.android.lifecycle.HiltViewModel
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
    private val iocEntryDao: IocEntryDao,
    private val iocDatabase: IocDatabase,
    private val remoteIocUpdater: RemoteIocUpdater
) : ViewModel() {

    val latestScan: StateFlow<ScanResult?> = repository.allScans
        .map { it.firstOrNull() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    val scanDiff: StateFlow<ScanOrchestrator.ScanDiff?> = repository.allScans
        .map { scans ->
            if (scans.size >= 2) orchestrator.computeDiff(scans[1], scans[0]) else null
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    // ── IOC state ─────────────────────────────────────────────────────────────

    private val bundledCount = iocDatabase.getAllBadPackages().size

    private val _iocEntryCount = MutableStateFlow(bundledCount)
    val iocEntryCount: StateFlow<Int> = _iocEntryCount.asStateFlow()

    private val _iocLastUpdated = MutableStateFlow<Long?>(null)
    val iocLastUpdated: StateFlow<Long?> = _iocLastUpdated.asStateFlow()

    private val _isUpdatingIoc = MutableStateFlow(false)
    val isUpdatingIoc: StateFlow<Boolean> = _isUpdatingIoc.asStateFlow()

    private val _iocErrorEvent = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val iocErrorEvent: SharedFlow<String> = _iocErrorEvent.asSharedFlow()

    init {
        viewModelScope.launch { refreshIocState() }
    }

    // ── Public functions ───────────────────────────────────────────────────────

    fun updateIoc() {
        viewModelScope.launch { doUpdate() }
    }

    fun runScan() {
        viewModelScope.launch {
            _isScanning.value = true
            try {
                val isStale = _iocLastUpdated.value == null ||
                    System.currentTimeMillis() - (_iocLastUpdated.value ?: 0L) > 24 * 60 * 60 * 1000L
                val hasOnlyBundled = _iocEntryCount.value <= bundledCount
                if (isStale || hasOnlyBundled) {
                    doUpdate()   // emits iocErrorEvent on failure, same as manual update
                }
                orchestrator.runFullScan()
            } finally {
                _isScanning.value = false
            }
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    @Suppress("TooGenericExceptionCaught") // remoteIocUpdater.update() can throw IOException or
    // SQLiteException; both are caught here to surface a user-visible error via the snackbar.
    private suspend fun doUpdate() {
        _isUpdatingIoc.value = true
        try {
            val fetched = remoteIocUpdater.update()
            if (fetched == 0) {
                _iocErrorEvent.tryEmit("Failed to update threat database. Check your connection.")
            }
            refreshIocState()
        } catch (e: Exception) {
            _iocErrorEvent.tryEmit("Threat database update failed: ${e.message}")
        } finally {
            _isUpdatingIoc.value = false
        }
    }

    private suspend fun refreshIocState() {
        _iocEntryCount.value = iocEntryDao.count() + bundledCount
        _iocLastUpdated.value = iocEntryDao.mostRecentFetchTime()
    }
}
