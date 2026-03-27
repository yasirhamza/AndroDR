package com.androdr.ui.device

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.repo.ScanRepository
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class DeviceAuditViewModel @Inject constructor(
    private val repository: ScanRepository
) : ViewModel() {

    /** All device posture findings from the most recent scan. */
    val deviceFindings: StateFlow<List<Finding>> = repository.allScans
        .map { scans ->
            scans.firstOrNull()?.findings
                ?.filter { it.category == FindingCategory.DEVICE_POSTURE }
                ?: emptyList()
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    /** The number of device findings that are currently triggered. */
    val triggeredCount: StateFlow<Int> = repository.allScans
        .map { scans ->
            scans.firstOrNull()?.findings
                ?.count { it.category == FindingCategory.DEVICE_POSTURE && it.triggered }
                ?: 0
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)
}
