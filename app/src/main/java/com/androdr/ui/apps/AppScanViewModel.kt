package com.androdr.ui.apps

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.model.AppRisk
import com.androdr.data.model.RiskLevel
import com.androdr.data.repo.ScanRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class AppScanViewModel @Inject constructor(
    private val repository: ScanRepository
) : ViewModel() {

    /** All app risks from the most recent scan, or an empty list if none exist. */
    val appRisks: StateFlow<List<AppRisk>> = repository.allScans
        .map { scans -> scans.firstOrNull()?.appRisks ?: emptyList() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _filterLevel = MutableStateFlow<RiskLevel?>(null)

    /** The currently active risk-level filter; null means show all risks. */
    val filterLevel: StateFlow<RiskLevel?> = _filterLevel.asStateFlow()

    /**
     * App risks filtered by [filterLevel] (null = all) and sorted by risk score
     * descending so the most dangerous entries appear first.
     */
    val filteredRisks: StateFlow<List<AppRisk>> = combine(appRisks, _filterLevel) { risks, level ->
        val filtered = if (level == null) risks else risks.filter { it.riskLevel == level }
        filtered.sortedByDescending { it.riskLevel.score }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    /** Updates the active filter. Pass null to show all risk levels. */
    fun setFilter(level: RiskLevel?) {
        _filterLevel.value = level
    }
}
