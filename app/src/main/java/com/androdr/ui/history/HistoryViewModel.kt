package com.androdr.ui.history

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
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class HistoryViewModel @Inject constructor(
    private val repository: ScanRepository,
    private val orchestrator: ScanOrchestrator
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
            // scans is ordered newest-first; the predecessor is at idx+1
            val predecessor = scans.getOrNull(idx + 1) ?: return@combine null
            orchestrator.diff(predecessor, selected)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    /**
     * Selects [scan] as the active detail item and triggers a diff computation
     * against its predecessor in [allScans].
     */
    fun selectScan(scan: ScanResult) {
        _selectedScan.value = scan
    }
}
