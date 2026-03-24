package com.androdr.ui.history

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.ScanRepository
import com.androdr.reporting.ReportExporter
import com.androdr.scanner.ScanOrchestrator
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class HistoryViewModel @Inject constructor(
    private val repository: ScanRepository,
    private val orchestrator: ScanOrchestrator,
    private val reportExporter: ReportExporter
) : ViewModel() {

    /** Full scan history, newest first. */
    val allScans: StateFlow<List<ScanResult>> = repository.allScans
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _selectedScan = MutableStateFlow<ScanResult?>(null)

    /** The scan currently selected for the detail view. */
    val selectedScan: StateFlow<ScanResult?> = _selectedScan.asStateFlow()

    /**
     * The diff between [selectedScan] and the scan that immediately preceded it
     * in the history list (i.e. the next oldest entry). Null when no scan is
     * selected or the selected scan has no predecessor.
     */
    val selectedDiff: StateFlow<ScanOrchestrator.ScanDiff?> =
        combine(allScans, _selectedScan) { scans, selected ->
            if (selected == null) return@combine null
            val idx = scans.indexOfFirst { it.id == selected.id }
            val predecessor = scans.getOrNull(idx + 1) ?: return@combine null
            orchestrator.computeDiff(predecessor, selected)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    /** Emits a [Uri] when a report is ready to share; null when idle or after consumption. */
    private val _shareUri = MutableStateFlow<Uri?>(null)
    val shareUri: StateFlow<Uri?> = _shareUri.asStateFlow()

    /** Whether a report export is currently in progress. */
    private val _exporting = MutableStateFlow(false)
    val exporting: StateFlow<Boolean> = _exporting.asStateFlow()

    fun selectScan(scan: ScanResult) {
        _selectedScan.value = scan
    }

    /**
     * Exports [scan] to a cached text file and emits its [FileProvider] URI via
     * [shareUri]. The Composable observes [shareUri] and fires the share intent.
     */
    fun exportReport(scan: ScanResult) {
        if (_exporting.value) return
        viewModelScope.launch {
            _exporting.value = true
            try {
                _shareUri.value = reportExporter.export(scan)
            } finally {
                _exporting.value = false
            }
        }
    }

    /** Call after the share intent has been launched to reset the URI state. */
    fun onShareConsumed() {
        _shareUri.value = null
    }
}
