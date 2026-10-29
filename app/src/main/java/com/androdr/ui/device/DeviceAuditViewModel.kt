package com.androdr.ui.device

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.repo.FindingsRepository
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
    private val findings: FindingsRepository
) : ViewModel() {

    /** The latest live scan with its findings (device posture is live state, spec §5.4). */
    private val latestScan = findings.latestLive()

    val deviceFindings: StateFlow<List<Finding>> = latestScan
        .map { scan ->
            scan?.findings
                ?.filter { it.category == FindingCategory.DEVICE_POSTURE }
                ?: emptyList()
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val triggeredCount: StateFlow<Int> = latestScan
        .map { scan ->
            scan?.findings
                ?.count { it.category == FindingCategory.DEVICE_POSTURE && it.triggered }
                ?: 0
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)
}
