package com.androdr.ui.device

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.model.DeviceFlag
import com.androdr.data.repo.ScanRepository
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

    /** All device flags from the most recent scan, or an empty list if none exist. */
    val deviceFlags: StateFlow<List<DeviceFlag>> = repository.allScans
        .map { scans -> scans.firstOrNull()?.deviceFlags ?: emptyList() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    /** The number of device flags that are currently triggered. */
    val triggeredCount: StateFlow<Int> = repository.allScans
        .map { scans ->
            scans.firstOrNull()?.deviceFlags?.count { it.isTriggered } ?: 0
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)
}
