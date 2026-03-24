package com.androdr.ui.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.ScanRepository
import com.androdr.scanner.ScanOrchestrator
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val orchestrator: ScanOrchestrator,
    private val repository: ScanRepository
) : ViewModel() {

    /** The most recent scan result, or null if no scans have been performed. */
    val latestScan: StateFlow<ScanResult?> = repository.allScans
        .map { it.firstOrNull() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    /**
     * Diff between the two most recent scans.
     * Computed reactively: whenever [allScans] emits at least two entries the
     * first two (newest first) are compared; otherwise null.
     */
    val scanDiff: StateFlow<ScanOrchestrator.ScanDiff?> = repository.allScans
        .map { scans ->
            if (scans.size >= 2) orchestrator.diff(scans[1], scans[0]) else null
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    /** Triggers a full scan and updates [isScanning] around the operation. */
    fun runScan() {
        viewModelScope.launch {
            _isScanning.value = true
            try {
                orchestrator.runFullScan()
            } finally {
                _isScanning.value = false
            }
        }
    }
}
